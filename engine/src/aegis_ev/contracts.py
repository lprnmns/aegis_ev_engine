from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import AdapterPlanner, ToolActionRequest, UnknownAdapterError, default_registry
from .audit import AuditLog, AuditVerificationResult, canonical_json, redact_value
from .evidence import EvidenceRecord, EvidenceStore, FindingRecord
from .models import AuthorizationProfile, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from .policy import PolicyEngine
from .reporting import create_report, render_report_json, render_report_markdown


@dataclass(frozen=True)
class CommandError:
    code: str
    message: str
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class CommandResponse:
    ok: bool
    command: str
    result: dict[str, Any] | None = None
    error: CommandError | None = None
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "ok": self.ok,
                "command": self.command,
                "result": self.result,
                "error": self.error.to_dict() if self.error else None,
                "warnings": self.warnings,
                "metadata": self.metadata,
            }
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def success(command: str, result: dict[str, Any] | None = None, *, warnings: list[str] | None = None) -> CommandResponse:
    return CommandResponse(
        ok=True,
        command=command,
        result=result or {},
        error=None,
        warnings=warnings or [],
        metadata={"contract_version": "engine-cli.v1"},
    )


def failure(
    command: str,
    code: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> CommandResponse:
    return CommandResponse(
        ok=False,
        command=command,
        result=None,
        error=CommandError(code=code, message=message, details=details),
        warnings=warnings or [],
        metadata={"contract_version": "engine-cli.v1"},
    )


def load_json_input(*, input_file: str | Path | None, stdin_text: str | None) -> tuple[dict[str, Any] | None, CommandResponse | None]:
    try:
        if input_file is not None:
            raw = Path(input_file).read_text(encoding="utf-8")
        else:
            raw = stdin_text or ""
    except OSError as exc:
        return None, failure("input", "input_read_failed", "Could not read JSON input", details={"error": str(exc)})

    if not raw.strip():
        return None, failure("input", "missing_input", "JSON input is required via --input-file or stdin")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, failure(
            "input",
            "invalid_json",
            "Input was not valid JSON",
            details={"line": exc.lineno, "column": exc.colno, "message": exc.msg},
        )
    if not isinstance(payload, dict):
        return None, failure("input", "invalid_input_shape", "Top-level JSON input must be an object")
    return payload, None


def run_contract_command(command: str, payload: dict[str, Any]) -> CommandResponse:
    try:
        if command == "validate-policy":
            return validate_policy(payload)
        if command == "plan-adapter":
            return plan_adapter(payload)
        if command == "render-report":
            return render_report(payload)
        if command == "verify-audit":
            return verify_audit(payload)
        return failure(command, "unsupported_command", f"Unsupported command: {command}")
    except (KeyError, TypeError, ValueError) as exc:
        return failure(command, "invalid_request", str(exc))


def validate_policy(payload: dict[str, Any]) -> CommandResponse:
    auth = _authorization_profile(_required_dict(payload, "authorization_profile"))
    budget_payload = payload.get("budget") or {}
    budget = RequestBudget(
        max_requests=int(budget_payload.get("max_requests", 1)),
        timeout_seconds=int(budget_payload.get("timeout_seconds", 10)),
        max_response_bytes=int(budget_payload.get("max_response_bytes", 1_000_000)),
    )
    intent = ToolIntent(
        adapter=str(payload.get("adapter", "contract")),
        target=str(_required(payload, "target")),
        impact=payload.get("impact", ImpactLevel.GREEN.value),
        budget=budget,
        reason=str(payload.get("reason", "")),
        action_type=str(payload.get("action_type", payload.get("action", "validate_policy"))),
        requires_authentication=bool(payload.get("requires_authentication", False)),
        requests_used=int(payload.get("requests_used", 0)),
        approval_id=payload.get("approval_id"),
        approval_granted=bool(payload.get("approval_granted", False)),
    )
    decision = PolicyEngine().evaluate(intent, auth, now=_optional_datetime(payload.get("now")))
    return success("validate-policy", {"policy_decision": _policy_decision_dict(decision)})


def plan_adapter(payload: dict[str, Any]) -> CommandResponse:
    request = ToolActionRequest(
        action_id=str(_required(payload, "action_id")),
        adapter_id=str(_required(payload, "adapter_id")),
        target=str(_required(payload, "target")),
        action=str(_required(payload, "action")),
        arguments=_dict_or_empty(payload.get("arguments")),
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=_authorization_profile(_required_dict(payload, "authorization_profile")),
        approval_token=payload.get("approval_token"),
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request)
    except UnknownAdapterError as exc:
        return failure("plan-adapter", "unknown_adapter", str(exc))
    return success("plan-adapter", {"plan": _plan_dict(plan)})


def render_report(payload: dict[str, Any]) -> CommandResponse:
    report_payload = _required_dict(payload, "report")
    output_format = str(payload.get("format", "json")).lower()
    if output_format not in {"json", "markdown"}:
        return failure("render-report", "unsupported_format", "format must be json or markdown")

    store = EvidenceStore()
    for evidence_payload in payload.get("evidence", []):
        store.add_evidence(EvidenceRecord(**evidence_payload))
    for finding_payload in payload.get("findings", []):
        store.add_finding(FindingRecord(**finding_payload))

    audit_result = None
    if payload.get("audit_verification") is not None:
        audit_result = _audit_verification(payload["audit_verification"])

    report = create_report(
        evidence_store=store,
        audit_verification=audit_result,
        project_name=str(_required(report_payload, "project_name")),
        report_id=report_payload.get("report_id"),
        created_at_utc=report_payload.get("created_at_utc"),
        customer_name=report_payload.get("customer_name"),
        environment=str(report_payload.get("environment", "development")),
        scope_summary=str(report_payload.get("scope_summary", "")),
        authorization_summary=str(report_payload.get("authorization_summary", "")),
        executive_summary=str(report_payload.get("executive_summary", "")),
        methodology_summary=str(report_payload.get("methodology_summary", "")),
        limitations=report_payload.get("limitations", []),
        generated_by=str(report_payload.get("generated_by", "Aegis EV")),
        tags=report_payload.get("tags", []),
    )
    content = render_report_markdown(report) if output_format == "markdown" else render_report_json(report)
    return success("render-report", {"format": output_format, "content": content})


def verify_audit(payload: dict[str, Any]) -> CommandResponse:
    audit_log = Path(str(_required(payload, "audit_log")))
    warnings: list[str] = []
    if not audit_log.exists():
        warnings.append("Audit log file does not exist; verification treats missing log as empty.")
    try:
        result = AuditLog(audit_log).verify()
    except ValueError as exc:
        return failure("verify-audit", "audit_verify_failed", str(exc))
    return success(
        "verify-audit",
        {
            "audit_log": str(audit_log),
            "valid": result.valid,
            "event_count": result.event_count,
            "last_hash": result.last_hash,
            "errors": result.errors,
        },
        warnings=warnings,
    )


def _authorization_profile(payload: dict[str, Any]) -> AuthorizationProfile:
    budget_payload = _required_dict(payload, "request_budget")
    return AuthorizationProfile(
        owner=str(_required(payload, "owner")),
        allowed_domains=list(payload.get("allowed_domains", [])),
        allowed_cidrs=list(payload.get("allowed_cidrs", [])),
        valid_from=_datetime(_required(payload, "valid_from")),
        valid_until=_datetime(_required(payload, "valid_until")),
        environment=str(_required(payload, "environment")),
        allowed_impact_levels=list(_required(payload, "allowed_impact_levels")),
        request_budget=PolicyBudget(
            max_requests=int(_required(budget_payload, "max_requests")),
            max_requests_per_minute=int(budget_payload.get("max_requests_per_minute", 30)),
            max_concurrency=int(budget_payload.get("max_concurrency", 2)),
        ),
        require_approval_for_authenticated_checks=bool(payload.get("require_approval_for_authenticated_checks", True)),
        require_approval_for_amber=bool(payload.get("require_approval_for_amber", True)),
        require_approval_for_production_amber=bool(payload.get("require_approval_for_production_amber", True)),
    )


def _policy_decision_dict(decision: Any) -> dict[str, Any]:
    public = decision.to_public_dict()
    public["decision"] = decision.decision.value
    return redact_value(public)


def _plan_dict(plan: Any) -> dict[str, Any]:
    return redact_value(
        {
            "allowed": plan.allowed,
            "policy_decision": _policy_decision_dict(plan.policy_decision),
            "adapter_id": plan.adapter_id,
            "action": plan.action,
            "normalized_target": plan.normalized_target,
            "sanitized_arguments": plan.sanitized_arguments,
            "impact_level": plan.impact_level,
            "required_approval": plan.required_approval,
            "estimated_budget": plan.estimated_budget,
            "audit_event_id": plan.audit_event_id,
            "command_preview": plan.command_preview,
            "execution_preview": plan.execution_preview,
            "denial_reason": plan.denial_reason,
            "decision_code": plan.decision_code,
            "dry_run": plan.dry_run,
        }
    )


def _audit_verification(payload: dict[str, Any]) -> AuditVerificationResult:
    return AuditVerificationResult(
        valid=bool(payload.get("valid", False)),
        event_count=int(payload.get("event_count", 0)),
        last_hash=str(payload.get("last_hash", "GENESIS")),
        errors=list(payload.get("errors", [])),
    )


def _required(payload: dict[str, Any], key: str) -> Any:
    if key not in payload:
        raise ValueError(f"Missing required field: {key}")
    return payload[key]


def _required_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = _required(payload, key)
    if not isinstance(value, dict):
        raise ValueError(f"Field must be an object: {key}")
    return value


def _dict_or_empty(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("arguments must be an object")
    return value


def _datetime(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("datetime fields must be ISO-8601 strings")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _optional_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    return _datetime(value)
