from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import AdapterPlanner, ToolActionRequest, UnknownAdapterError, default_registry
from .attack_surface import build_attack_surface_graph, evidence_from_attack_surface_graph, attack_surface_report_section
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
from .checks.web_headers import (
    WebHeaderAnalysisInput,
    analyze_web_headers,
    evidence_from_web_header_check,
    finding_from_web_header_check,
)
from .demo_flow import run_demo_flow_from_payload
from .evidence import EvidenceRecord, EvidenceStore, FindingRecord
from .http_fetch import (
    SafeHttpFetchRequest,
    analyze_headers_from_fetch_result,
    evidence_from_fetch_result,
    fixture_transport,
    safe_http_fetch,
)
from .fingerprinting import (
    TechnologyFingerprintInput,
    evidence_from_fingerprint,
    fingerprint_technology,
    findings_from_fingerprint,
)
from .imports import evidence_from_import_result, import_har, import_openapi, import_postman
from .models import AuthorizationProfile, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from .policy import PolicyEngine
from .portfolio_demo import run_portfolio_demo_from_payload
from .projects import (
    ProjectWorkspaceStore,
    create_project_record,
    create_session_record,
    create_target_record,
    scope_from_dict,
    validate_target_against_scope,
)
from .reporting import create_report, render_report_json, render_report_markdown
from .vuln_intel import (
    evidence_from_vulnerability_mapping,
    findings_from_vulnerability_mapping,
    map_vulnerability_intelligence,
    vulnerability_intelligence_report_section,
)


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
        if command == "analyze-web-headers":
            return analyze_web_headers_command(payload)
        if command == "import-openapi":
            return import_openapi_command(payload)
        if command == "import-postman":
            return import_postman_command(payload)
        if command == "import-har":
            return import_har_command(payload)
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
        if command == "create-project":
            return create_project(payload)
        if command == "get-project":
            return get_project(payload)
        if command == "list-projects":
            return list_projects(payload)
        if command == "add-target":
            return add_target(payload)
        if command == "list-targets":
            return list_targets(payload)
        if command == "create-session":
            return create_session(payload)
        if command == "get-session":
            return get_session(payload)
        if command == "list-sessions":
            return list_sessions(payload)
        if command == "update-session-status":
            return update_session_status(payload)
        if command == "validate-project-target":
            return validate_project_target(payload)
        if command == "link-project-reference":
            return link_project_reference(payload)
        if command in {"run-demo-flow", "demo-flow"}:
            return run_demo_flow_command(payload, command=command)
        if command == "fetch-http-metadata":
            return fetch_http_metadata_command(payload)
        if command == "fetch-and-analyze-headers":
            return fetch_and_analyze_headers_command(payload)
        if command == "fingerprint-technology":
            return fingerprint_technology_command(payload)
        if command == "build-attack-surface-graph":
            return build_attack_surface_graph_command(payload)
        if command == "map-vulnerability-intelligence":
            return map_vulnerability_intelligence_command(payload)
        if command == "run-portfolio-demo":
            return run_portfolio_demo_command(payload)
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


def analyze_web_headers_command(payload: dict[str, Any]) -> CommandResponse:
    warnings: list[str] = []
    authorization = _authorization_profile(_required_dict(payload, "authorization_profile"))
    request = ToolActionRequest(
        action_id=str(payload.get("action_id", "analyze_web_headers")),
        adapter_id="web_header_config_check",
        target=str(_required(payload, "target")),
        action="analyze_headers",
        arguments={"headers": _required_dict(payload, "headers")},
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=authorization,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request)
    except UnknownAdapterError as exc:
        return failure("analyze-web-headers", "unknown_adapter", str(exc))

    result: dict[str, Any] = {"plan": _plan_dict(plan), "checks": [], "evidence": [], "findings": []}
    if not plan.allowed:
        return success("analyze-web-headers", result, warnings=warnings)

    analysis_input = WebHeaderAnalysisInput(
        target=request.target,
        normalized_target=plan.normalized_target,
        status_code=payload.get("status_code"),
        headers=_required_dict(payload, "headers"),
        content_type=payload.get("content_type"),
        protocol=payload.get("protocol"),
        tls_summary=_mapping_or_none(payload.get("tls_summary")),
        observed_redirects=tuple(payload.get("observed_redirects", [])),
        source_reference=payload.get("source_reference"),
        request_origin=payload.get("request_origin"),
        security_txt_present=payload.get("security_txt_present"),
    )
    checks = analyze_web_headers(analysis_input)
    evidence_records = [evidence_from_web_header_check(item, related_audit_event_id=plan.audit_event_id) for item in checks]
    finding_records = [finding_from_web_header_check(item, evidence) for item, evidence in zip(checks, evidence_records, strict=True)]
    result["checks"] = [item.to_dict() for item in checks]
    result["evidence"] = [item.to_dict() for item in evidence_records]
    result["findings"] = [item.to_dict() for item in finding_records]
    return success("analyze-web-headers", result, warnings=warnings)


def fetch_http_metadata_command(payload: dict[str, Any]) -> CommandResponse:
    return _fetch_http(payload, analyze=False)


def fetch_and_analyze_headers_command(payload: dict[str, Any]) -> CommandResponse:
    return _fetch_http(payload, analyze=True)


def fingerprint_technology_command(payload: dict[str, Any]) -> CommandResponse:
    command = "fingerprint-technology"
    authorization = _authorization_profile(_required_dict(payload, "authorization_profile"))
    target = str(_required(payload, "target"))
    metadata = _required_dict(payload, "metadata")
    request = ToolActionRequest(
        action_id=str(payload.get("action_id", "fingerprint_technology")),
        adapter_id="technology_fingerprint",
        target=target,
        action="fingerprint_from_metadata",
        arguments={"metadata": metadata},
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=authorization,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request, audit_log=_optional_audit_log(payload))
    except UnknownAdapterError as exc:
        return failure(command, "unknown_adapter", str(exc))
    response: dict[str, Any] = {"plan": _plan_dict(plan), "fingerprint": None, "evidence": None, "findings": []}
    if not plan.allowed:
        return success(command, response)
    fetch_payload = metadata.get("fetch_result") if isinstance(metadata.get("fetch_result"), dict) else {}
    merged_headers = _dict_or_empty(metadata.get("headers") or fetch_payload.get("headers") or {})
    fingerprint = fingerprint_technology(
        TechnologyFingerprintInput(
            target=target,
            normalized_target=metadata.get("normalized_target") or fetch_payload.get("normalized_target") or plan.normalized_target,
            source_type=str(metadata.get("source_type", "cli_supplied_metadata")),
            headers=merged_headers,
            final_url=metadata.get("final_url") or fetch_payload.get("final_url"),
            redirect_chain=tuple(metadata.get("redirect_chain") or fetch_payload.get("redirect_chain") or []),
            content_type=metadata.get("content_type") or fetch_payload.get("content_type"),
            content_length=metadata.get("content_length") or fetch_payload.get("content_length"),
            capped_html_snippet=metadata.get("capped_html_snippet"),
            script_src=tuple(metadata.get("script_src", [])),
            link_href=tuple(metadata.get("link_href", [])),
            meta_tags=tuple(metadata.get("meta_tags", [])),
            endpoint_inventory=tuple(metadata.get("endpoint_inventory", [])),
            evidence_ids=tuple(metadata.get("evidence_ids", [])),
            created_at_utc=metadata.get("created_at_utc"),
            metadata={"command": command},
        )
    )
    evidence = evidence_from_fingerprint(fingerprint, related_adapter_id="technology_fingerprint")
    response["fingerprint"] = fingerprint.to_dict()
    response["evidence"] = evidence.to_dict()
    response["findings"] = [item.to_dict() for item in findings_from_fingerprint(fingerprint, evidence)]
    return success(command, response, warnings=list(fingerprint.warnings))


def build_attack_surface_graph_command(payload: dict[str, Any]) -> CommandResponse:
    command = "build-attack-surface-graph"
    authorization = _authorization_profile(_required_dict(payload, "authorization_profile"))
    target = str(_required(payload, "target"))
    graph_input = _required_dict(payload, "graph_input")
    request = ToolActionRequest(
        action_id=str(payload.get("action_id", "build_attack_surface_graph")),
        adapter_id="attack_surface_graph",
        target=target,
        action="build_attack_surface_graph",
        arguments={"graph_input": graph_input},
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=authorization,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request, audit_log=_optional_audit_log(payload))
    except UnknownAdapterError as exc:
        return failure(command, "unknown_adapter", str(exc))
    response: dict[str, Any] = {"plan": _plan_dict(plan), "graph": None, "evidence": None, "report_section": None}
    if not plan.allowed:
        return success(command, response)
    graph = build_attack_surface_graph(graph_input)
    evidence = evidence_from_attack_surface_graph(graph)
    response["graph"] = graph.to_dict()
    response["evidence"] = evidence.to_dict()
    response["report_section"] = attack_surface_report_section(graph)
    return success(command, response, warnings=list(graph.warnings))


def map_vulnerability_intelligence_command(payload: dict[str, Any]) -> CommandResponse:
    command = "map-vulnerability-intelligence"
    authorization = _authorization_profile(_required_dict(payload, "authorization_profile"))
    target = str(_required(payload, "target"))
    mapping_input = _required_dict(payload, "mapping_input")
    request = ToolActionRequest(
        action_id=str(payload.get("action_id", "map_vulnerability_intelligence")),
        adapter_id="vulnerability_intelligence",
        target=target,
        action="map_vulnerability_intelligence",
        arguments={"mapping_input": mapping_input},
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=authorization,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(request, audit_log=_optional_audit_log(payload))
    except UnknownAdapterError as exc:
        return failure(command, "unknown_adapter", str(exc))
    response: dict[str, Any] = {"plan": _plan_dict(plan), "mapping": None, "evidence": None, "findings": [], "report_section": None}
    if not plan.allowed:
        return success(command, response)
    mapping = map_vulnerability_intelligence(mapping_input)
    evidence = evidence_from_vulnerability_mapping(mapping)
    response["mapping"] = mapping.to_dict()
    response["evidence"] = evidence.to_dict()
    response["findings"] = [item.to_dict() for item in findings_from_vulnerability_mapping(mapping)]
    response["report_section"] = vulnerability_intelligence_report_section(mapping)
    return success(command, response, warnings=list(mapping.warnings))


def _fetch_http(payload: dict[str, Any], *, analyze: bool) -> CommandResponse:
    command = "fetch-and-analyze-headers" if analyze else "fetch-http-metadata"
    if payload.get("headers"):
        raise ValueError("custom request headers are not accepted by safe HTTP fetch")
    authorization = _authorization_profile(_required_dict(payload, "authorization_profile"))
    method = str(payload.get("method", "HEAD")).upper()
    target = str(_required(payload, "target"))
    request_context = {
        "method": method,
        "max_redirects": int(payload.get("max_redirects", 3)),
        "timeout_seconds": int(payload.get("timeout_seconds", 5)),
        "no_body_stored": True,
    }
    plan_request = ToolActionRequest(
        action_id=str(payload.get("action_id", command.replace("-", "_"))),
        adapter_id="safe_http_fetch",
        target=target,
        action="fetch_and_analyze_headers" if analyze else "fetch_metadata",
        arguments={"request": request_context},
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        actor=str(payload.get("actor", "contract")),
        authorization_profile=authorization,
        dry_run=bool(payload.get("dry_run", True)),
        requests_used=int(payload.get("requests_used", 0)),
    )
    try:
        plan = AdapterPlanner(default_registry()).plan(plan_request, audit_log=_optional_audit_log(payload))
    except UnknownAdapterError as exc:
        return failure(command, "unknown_adapter", str(exc))
    fetch_request = SafeHttpFetchRequest(
        fetch_id=str(payload.get("fetch_id", command.replace("-", "_"))),
        target=target,
        authorization_profile=authorization,
        method=method,
        requested_by=str(payload.get("requested_by", payload.get("actor", "contract"))),
        actor=str(payload.get("actor", "contract")),
        max_redirects=int(payload.get("max_redirects", 3)),
        timeout_seconds=int(payload.get("timeout_seconds", 5)),
        requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
        requests_used=int(payload.get("requests_used", 0)),
        now=_optional_datetime(payload.get("now")),
        metadata={"command": command},
    )
    transport = fixture_transport(_required_dict(payload, "transport_fixture")) if payload.get("transport_fixture") else None
    result = safe_http_fetch(fetch_request, transport=transport, audit_log=_optional_audit_log(payload))
    response: dict[str, Any] = {"plan": _plan_dict(plan), "fetch": result.to_dict()}
    if result.allowed and not result.error:
        evidence = evidence_from_fetch_result(result)
        response["evidence"] = evidence.to_dict()
    else:
        response["evidence"] = None
    if analyze:
        checks, evidence_records, finding_records = analyze_headers_from_fetch_result(result)
        response["checks"] = checks
        response["header_evidence"] = [item.to_dict() for item in evidence_records]
        response["findings"] = [item.to_dict() for item in finding_records]
    if not plan.allowed:
        response["fetch"] = result.to_dict()
    return success(command, response, warnings=list(result.warnings))


def import_openapi_command(payload: dict[str, Any]) -> CommandResponse:
    return _import_api_description(
        command="import-openapi",
        payload=payload,
        importer=import_openapi,
        adapter_action="import_openapi",
    )


def import_postman_command(payload: dict[str, Any]) -> CommandResponse:
    return _import_api_description(
        command="import-postman",
        payload=payload,
        importer=import_postman,
        adapter_action="import_postman",
    )


def import_har_command(payload: dict[str, Any]) -> CommandResponse:
    return _import_api_description(
        command="import-har",
        payload=payload,
        importer=import_har,
        adapter_action="import_har",
    )


def _import_api_description(command: str, payload: dict[str, Any], importer: Any, adapter_action: str) -> CommandResponse:
    source_name = payload.get("source_name")
    now = _optional_datetime(payload.get("now"))
    data = _required_dict(payload, "data")
    warnings: list[str] = []
    plan_payload = payload.get("authorization_profile")
    plan_dict = None
    if plan_payload is not None:
        target = str(payload.get("target", "https://example.com"))
        request = ToolActionRequest(
            action_id=str(payload.get("action_id", command.replace("-", "_"))),
            adapter_id="api_import",
            target=target,
            action=adapter_action,
            arguments={"data": data},
            requested_impact_level=payload.get("requested_impact_level", ImpactLevel.GREEN.value),
            actor=str(payload.get("actor", "contract")),
            authorization_profile=_authorization_profile(_required_dict(payload, "authorization_profile")),
            dry_run=bool(payload.get("dry_run", True)),
            requests_used=int(payload.get("requests_used", 0)),
        )
        try:
            plan = AdapterPlanner(default_registry()).plan(request)
        except UnknownAdapterError as exc:
            return failure(command, "unknown_adapter", str(exc))
        plan_dict = _plan_dict(plan)
        if not plan.allowed:
            return success(command, {"plan": plan_dict, "import_result": None, "evidence": None}, warnings=warnings)

    result = importer(data, source_name=source_name, now=now)
    evidence = evidence_from_import_result(result)
    result_payload = result.to_dict()
    result_payload["evidence_ids"] = [evidence.evidence_id]
    response = {
        "import_result": result_payload,
        "endpoint_count": result.endpoint_count,
        "evidence": evidence.to_dict(),
    }
    if plan_dict is not None:
        response["plan"] = plan_dict
    warnings.extend(result.warnings)
    if result.errors:
        return failure(command, "invalid_import", "; ".join(result.errors), details=response, warnings=warnings)
    return success(command, response, warnings=warnings)


def create_project(payload: dict[str, Any]) -> CommandResponse:
    store, store_path = _workspace_store(payload)
    project = create_project_record(_required_dict(payload, "project"))
    store.create_project(project)
    _export_workspace_if_configured(store, store_path)
    return success("create-project", {"project": project.to_dict()})


def get_project(payload: dict[str, Any]) -> CommandResponse:
    store, _store_path = _workspace_store(payload)
    project = store.get_project(str(_required(payload, "project_id")))
    return success("get-project", {"project": project.to_dict()})


def list_projects(payload: dict[str, Any]) -> CommandResponse:
    store, _store_path = _workspace_store(payload)
    return success("list-projects", {"projects": [project.to_dict() for project in store.list_projects()]})


def add_target(payload: dict[str, Any]) -> CommandResponse:
    store, store_path = _workspace_store(payload)
    project = store.get_project(str(_required(payload, "project_id")))
    target = create_target_record(_required_dict(payload, "target"), project)
    stored = store.add_target(project.project_id, target)
    _export_workspace_if_configured(store, store_path)
    return success("add-target", {"target": stored.to_dict(), "project": store.get_project(project.project_id).to_dict()})


def list_targets(payload: dict[str, Any]) -> CommandResponse:
    store, _store_path = _workspace_store(payload)
    targets = [target.to_dict() for target in store.list_project_targets(str(_required(payload, "project_id")))]
    return success("list-targets", {"targets": targets})


def create_session(payload: dict[str, Any]) -> CommandResponse:
    store, store_path = _workspace_store(payload)
    session = create_session_record(_required_dict(payload, "session"))
    store.create_session(session)
    _export_workspace_if_configured(store, store_path)
    return success("create-session", {"session": session.to_dict()})


def get_session(payload: dict[str, Any]) -> CommandResponse:
    store, _store_path = _workspace_store(payload)
    session = store.get_session(str(_required(payload, "session_id")))
    return success("get-session", {"session": session.to_dict()})


def list_sessions(payload: dict[str, Any]) -> CommandResponse:
    store, _store_path = _workspace_store(payload)
    sessions = [session.to_dict() for session in store.list_sessions(payload.get("project_id"))]
    return success("list-sessions", {"sessions": sessions})


def update_session_status(payload: dict[str, Any]) -> CommandResponse:
    store, store_path = _workspace_store(payload)
    session = store.update_session_status(str(_required(payload, "session_id")), str(_required(payload, "status")))
    _export_workspace_if_configured(store, store_path)
    return success("update-session-status", {"session": session.to_dict()})


def validate_project_target(payload: dict[str, Any]) -> CommandResponse:
    scope = scope_from_dict(_required_dict(payload, "scope"))
    result = validate_target_against_scope(
        str(_required(payload, "value")),
        str(_required(payload, "target_type")),
        scope,
        owner=str(payload.get("owner", scope.owner_attestation or scope.scope_id)),
        now=_optional_datetime(payload.get("now")),
    )
    return success("validate-project-target", result)


def link_project_reference(payload: dict[str, Any]) -> CommandResponse:
    store, store_path = _workspace_store(payload)
    project_id = str(_required(payload, "project_id"))
    reference_type = str(_required(payload, "reference_type"))
    reference_id = str(_required(payload, "reference_id"))
    if reference_type == "import":
        project = store.add_import_reference(project_id, reference_id)
    elif reference_type == "evidence":
        project = store.add_evidence_reference(project_id, reference_id)
    elif reference_type == "finding":
        project = store.add_finding_reference(project_id, reference_id)
    elif reference_type == "report":
        project = store.add_report_reference(project_id, reference_id)
    else:
        raise ValueError("reference_type must be import, evidence, finding, or report")
    _export_workspace_if_configured(store, store_path)
    return success("link-project-reference", {"project": project.to_dict()})


def run_demo_flow_command(payload: dict[str, Any], *, command: str = "run-demo-flow") -> CommandResponse:
    result = run_demo_flow_from_payload(payload)
    return success(command, {"demo": result.to_dict()}, warnings=list(result.warnings))


def run_portfolio_demo_command(payload: dict[str, Any]) -> CommandResponse:
    result = run_portfolio_demo_from_payload(payload)
    return success("run-portfolio-demo", {"demo": result.to_dict()}, warnings=list(result.warnings))


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


def _mapping_or_none(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("value must be an object")
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


def _optional_audit_log(payload: dict[str, Any]) -> AuditLog | None:
    if not payload.get("audit_log"):
        return None
    return AuditLog(str(payload["audit_log"]))


def _workspace_store(payload: dict[str, Any]) -> tuple[ProjectWorkspaceStore, Path | None]:
    store_path = payload.get("workspace_store") or payload.get("project_store")
    if store_path:
        path = Path(str(store_path))
        return ProjectWorkspaceStore.import_json(path), path
    return ProjectWorkspaceStore(), None


def _export_workspace_if_configured(store: ProjectWorkspaceStore, store_path: Path | None) -> None:
    if store_path is not None:
        store.export_json(store_path)


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
