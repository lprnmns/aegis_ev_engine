from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import AdapterPlanner, ToolActionRequest, UnknownAdapterError, default_registry
from .approvals import (
    ApprovalActorType,
    ApprovalRequest,
    ApprovalStore,
    append_approval_audit_event,
    approval_allows_request,
    approval_from_policy_decision,
    apply_approval_to_intent,
)
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
        if command == "create-approval":
            return create_approval(payload)
        if command == "list-approvals":
            return list_approvals(payload)
        if command == "approve-action":
            return approve_action(payload)
        if command == "reject-action":
            return reject_action(payload)
        if command == "consume-approval":
            return consume_approval(payload)
        if command == "approval-status":
            return approval_status(payload)
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
    now = _optional_datetime(payload.get("now"))
    warnings: list[str] = []
    policy_engine = PolicyEngine()
    initial_decision = policy_engine.evaluate(intent, auth, now=now)
    approval = _resolve_approval_for_request(
        payload,
        target=intent.target,
        normalized_target=initial_decision.normalized_target,
        action_type=intent.action_type,
        impact_level=intent.impact,
        adapter_id=intent.adapter,
        adapter_action=None,
        now=now,
        warnings=warnings,
    )
    resolved_intent = apply_approval_to_intent(
        intent,
        approval,
        normalized_target=initial_decision.normalized_target,
        now=now,
    )
    decision = policy_engine.evaluate(resolved_intent, auth, now=now)
    result: dict[str, Any] = {"policy_decision": _policy_decision_dict(decision)}
    if decision.required_approval and payload.get("create_approval_if_required"):
        request = _create_policy_approval_request(
            payload,
            decision=decision,
            sanitized_arguments={},
            now=now,
        )
        result["approval_request"] = request.to_dict()
    elif approval is not None:
        result["approval"] = approval.to_dict()
        if decision.allowed and payload.get("consume_approval_on_allow") and payload.get("approval_store"):
            consumed = _consume_store_approval(
                approval_id=approval.approval_id,
                store_path=payload["approval_store"],
                consumer=str(payload.get("approval_consumer", "policy")),
                audit_log_path=payload.get("audit_log"),
                now=now,
            )
            result["consumed_approval"] = consumed.to_dict()
    return success("validate-policy", result, warnings=warnings)


def plan_adapter(payload: dict[str, Any]) -> CommandResponse:
    warnings: list[str] = []
    now = _optional_datetime(payload.get("now"))
    requested_impact = payload.get("requested_impact_level", ImpactLevel.GREEN.value)
    temp_request = ToolActionRequest(
        action_id=str(_required(payload, "action_id")),
        adapter_id=str(_required(payload, "adapter_id")),
        target=str(_required(payload, "target")),
        action=str(_required(payload, "action")),
        arguments=_dict_or_empty(payload.get("arguments")),
        requested_impact_level=requested_impact,
        actor=str(payload.get("actor", "contract")),
        authorization_profile=_authorization_profile(_required_dict(payload, "authorization_profile")),
        approval_token=None,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        preflight_plan = AdapterPlanner(default_registry()).plan(temp_request)
    except UnknownAdapterError as exc:
        return failure("plan-adapter", "unknown_adapter", str(exc))
    approval = _resolve_approval_for_request(
        payload,
        target=temp_request.target,
        normalized_target=preflight_plan.normalized_target,
        action_type=temp_request.action,
        impact_level=requested_impact,
        adapter_id=temp_request.adapter_id,
        adapter_action=temp_request.action,
        now=now,
        warnings=warnings,
    )
    request = ToolActionRequest(
        action_id=temp_request.action_id,
        adapter_id=temp_request.adapter_id,
        target=temp_request.target,
        action=temp_request.action,
        arguments=temp_request.arguments,
        requested_impact_level=temp_request.requested_impact_level,
        actor=temp_request.actor,
        authorization_profile=temp_request.authorization_profile,
        approval_token=approval.approval_id if approval is not None else None,
        dry_run=temp_request.dry_run,
        requests_used=temp_request.requests_used,
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request)
    except UnknownAdapterError as exc:
        return failure("plan-adapter", "unknown_adapter", str(exc))
    result: dict[str, Any] = {"plan": _plan_dict(plan)}
    if plan.required_approval and payload.get("create_approval_if_required"):
        request_record = _create_policy_approval_request(
            payload,
            decision=plan.policy_decision,
            sanitized_arguments=plan.sanitized_arguments,
            adapter_id=plan.adapter_id,
            adapter_action=plan.action,
            now=now,
        )
        result["approval_request"] = request_record.to_dict()
        result["plan"]["approval_id"] = request_record.approval_id
        result["plan"]["approval_status"] = request_record.status
    elif approval is not None:
        result["approval"] = approval.to_dict()
        result["plan"]["approval_id"] = approval.approval_id
        result["plan"]["approval_status"] = approval.status
        if plan.allowed and payload.get("consume_approval_on_allow") and payload.get("approval_store"):
            consumed = _consume_store_approval(
                approval_id=approval.approval_id,
                store_path=payload["approval_store"],
                consumer=str(payload.get("approval_consumer", request.actor)),
                audit_log_path=payload.get("audit_log"),
                now=now,
            )
            result["consumed_approval"] = consumed.to_dict()
    return success("plan-adapter", result, warnings=warnings)


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


def create_approval(payload: dict[str, Any]) -> CommandResponse:
    store_path = _approval_store_path(payload)
    store = ApprovalStore.import_json(store_path)
    approval = ApprovalRequest(**_required_dict(payload, "approval"))
    if payload.get("audit_log"):
        event = append_approval_audit_event(
            AuditLog(str(payload["audit_log"])),
            approval,
            event_type="approval_requested",
            actor=str(payload.get("audit_actor", approval.requested_by)),
        )
        approval = ApprovalRequest(**(approval.to_dict() | {"related_audit_event_id": event.event_id}))
    store.add(approval)
    store.export_json(store_path)
    return success("create-approval", {"approval": approval.to_dict()})


def list_approvals(payload: dict[str, Any]) -> CommandResponse:
    store = ApprovalStore.import_json(_approval_store_path(payload))
    now = _optional_datetime(payload.get("now"))
    approvals = store.list_pending(now=now) if payload.get("pending_only") else store.list_approvals(now=now)
    return success("list-approvals", {"approvals": [item.to_dict() for item in approvals]})


def approve_action(payload: dict[str, Any]) -> CommandResponse:
    store_path = _approval_store_path(payload)
    store = ApprovalStore.import_json(store_path)
    approval = store.approve(
        str(_required(payload, "approval_id")),
        approved_by=str(_required(payload, "approved_by")),
        actor_type=payload.get("actor_type", ApprovalActorType.HUMAN.value),
        decision_reason=str(payload.get("decision_reason", "")),
        now=_optional_datetime(payload.get("now")),
    )
    if payload.get("audit_log"):
        event = append_approval_audit_event(
            AuditLog(str(payload["audit_log"])),
            approval,
            event_type="approval_approved",
            actor=str(payload["approved_by"]),
            decision_reason=approval.decision_reason,
        )
        approval = ApprovalRequest(**(approval.to_dict() | {"related_audit_event_id": event.event_id}))
        store._items[approval.approval_id] = approval
    store.export_json(store_path)
    return success("approve-action", {"approval": approval.to_dict()})


def reject_action(payload: dict[str, Any]) -> CommandResponse:
    store_path = _approval_store_path(payload)
    store = ApprovalStore.import_json(store_path)
    approval = store.reject(
        str(_required(payload, "approval_id")),
        rejected_by=str(_required(payload, "rejected_by")),
        actor_type=payload.get("actor_type", ApprovalActorType.HUMAN.value),
        decision_reason=str(payload.get("decision_reason", "")),
        now=_optional_datetime(payload.get("now")),
    )
    if payload.get("audit_log"):
        event = append_approval_audit_event(
            AuditLog(str(payload["audit_log"])),
            approval,
            event_type="approval_rejected",
            actor=str(payload["rejected_by"]),
            decision_reason=approval.decision_reason,
        )
        approval = ApprovalRequest(**(approval.to_dict() | {"related_audit_event_id": event.event_id}))
        store._items[approval.approval_id] = approval
    store.export_json(store_path)
    return success("reject-action", {"approval": approval.to_dict()})


def consume_approval(payload: dict[str, Any]) -> CommandResponse:
    consumed = _consume_store_approval(
        approval_id=str(_required(payload, "approval_id")),
        store_path=_approval_store_path(payload),
        consumer=str(_required(payload, "consumer")),
        audit_log_path=payload.get("audit_log"),
        now=_optional_datetime(payload.get("now")),
    )
    return success("consume-approval", {"approval": consumed.to_dict()})


def approval_status(payload: dict[str, Any]) -> CommandResponse:
    store = ApprovalStore.import_json(_approval_store_path(payload))
    approval = store.get(str(_required(payload, "approval_id")), now=_optional_datetime(payload.get("now")))
    return success("approval-status", {"approval": approval.to_dict()})


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
            "approval_id": plan.approval_id,
            "approval_status": plan.approval_status,
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


def _approval_store_path(payload: dict[str, Any]) -> Path:
    return Path(str(_required(payload, "approval_store")))


def _create_policy_approval_request(
    payload: dict[str, Any],
    *,
    decision: Any,
    sanitized_arguments: dict[str, Any],
    adapter_id: str | None = None,
    adapter_action: str | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    approval_context = _required_dict(payload, "approval_request")
    request = approval_from_policy_decision(
        decision,
        requested_by=str(_required(approval_context, "requested_by")),
        requested_actor_type=approval_context.get("requested_actor_type", ApprovalActorType.HUMAN.value),
        adapter_id=adapter_id,
        adapter_action=adapter_action,
        sanitized_arguments=sanitized_arguments,
        expires_at_utc=approval_context.get("expires_at_utc"),
        tags=tuple(approval_context.get("tags", [])),
        metadata=_dict_or_empty(approval_context.get("metadata")),
    )
    store_path = _approval_store_path(payload)
    store = ApprovalStore.import_json(store_path)
    if payload.get("audit_log"):
        event = append_approval_audit_event(
            AuditLog(str(payload["audit_log"])),
            request,
            event_type="approval_requested",
            actor=str(approval_context.get("requested_by")),
        )
        request = ApprovalRequest(**(request.to_dict() | {"related_audit_event_id": event.event_id}))
    store.add(request)
    store.export_json(store_path)
    return request


def _resolve_approval_for_request(
    payload: dict[str, Any],
    *,
    target: str,
    normalized_target: str | None,
    action_type: str,
    impact_level: ImpactLevel | str,
    adapter_id: str | None,
    adapter_action: str | None,
    now: datetime | None,
    warnings: list[str],
) -> ApprovalRequest | None:
    approval = None
    if payload.get("approval") is not None:
        approval = ApprovalRequest(**_required_dict(payload, "approval"))
    elif payload.get("approval_id") and payload.get("approval_store"):
        store = ApprovalStore.import_json(Path(str(payload["approval_store"])))
        approval = store.get(str(payload["approval_id"]), now=now)
    if approval is None:
        return None
    if not approval_allows_request(
        approval,
        target=target,
        normalized_target=normalized_target,
        action_type=action_type,
        impact_level=impact_level,
        adapter_id=adapter_id,
        adapter_action=adapter_action,
        now=now,
    ):
        warnings.append("Provided approval did not match the request scope and was ignored.")
        return None
    return approval


def _consume_store_approval(
    *,
    approval_id: str,
    store_path: str | Path,
    consumer: str,
    audit_log_path: str | Path | None,
    now: datetime | None,
) -> ApprovalRequest:
    store = ApprovalStore.import_json(Path(store_path))
    approval = store.consume(approval_id, consumer=consumer, now=now)
    if audit_log_path:
        event = append_approval_audit_event(
            AuditLog(str(audit_log_path)),
            approval,
            event_type="approval_consumed",
            actor=consumer,
            decision_reason=approval.decision_reason,
        )
        approval = ApprovalRequest(**(approval.to_dict() | {"related_audit_event_id": event.event_id}))
        store._items[approval.approval_id] = approval
    store.export_json(Path(store_path))
    return approval
