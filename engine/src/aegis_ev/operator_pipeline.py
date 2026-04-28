from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attack_surface import attack_surface_report_section, build_attack_surface_graph, evidence_from_attack_surface_graph
from .audit import AuditLog, AuditVerificationResult, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceStore, EvidenceType, FindingConfidence
from .fingerprinting import TechnologyFingerprintInput, evidence_from_fingerprint, fingerprint_technology
from .http_fetch import SafeHttpFetchRequest, Transport, analyze_headers_from_fetch_result, evidence_from_fetch_result, fixture_transport, safe_http_fetch
from .portfolio_demo import PortfolioDemoInput
from .projects import ProjectWorkspaceStore, ScopeDefinition, SessionRecord, create_project_record, create_target_record
from .recon_planner import evidence_from_recon_plan, plan_safe_recon, recon_plan_report_section
from .reporting import create_report, render_report_json, render_report_markdown
from .tool_adapters import evidence_from_tool_plan, plan_tool_action
from .vuln_intel import evidence_from_vulnerability_mapping, map_vulnerability_intelligence, vulnerability_intelligence_report_section


PIPELINE_ID = "authorized_portfolio_operator_pipeline_v1"
DEFAULT_CREATED_AT = "2026-01-01T00:00:00+00:00"


@dataclass(frozen=True)
class PortfolioOperatorPipelineResult:
    pipeline_id: str
    created_at_utc: str
    project_id: str | None
    session_id: str | None
    target: str
    normalized_target: str | None
    fetch_summary: dict[str, Any]
    header_check_summary: dict[str, Any]
    fingerprint_summary: dict[str, Any]
    attack_surface_summary: dict[str, Any]
    vulnerability_intel_summary: dict[str, Any]
    recon_plan_summary: dict[str, Any]
    tool_capability_summary: dict[str, Any]
    evidence_count: int
    finding_count: int
    hypothesis_count: int
    report_paths: dict[str, str] = field(default_factory=dict)
    reports: dict[str, str] = field(default_factory=dict)
    audit_verification_status: dict[str, Any] = field(default_factory=dict)
    live_request_performed: bool = False
    no_body_stored: bool = True
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "pipeline_id": self.pipeline_id,
                "created_at_utc": self.created_at_utc,
                "project_id": self.project_id,
                "session_id": self.session_id,
                "target": redact_target(self.target),
                "normalized_target": redact_target(self.normalized_target),
                "fetch_summary": self.fetch_summary,
                "header_check_summary": self.header_check_summary,
                "fingerprint_summary": self.fingerprint_summary,
                "attack_surface_summary": self.attack_surface_summary,
                "vulnerability_intel_summary": self.vulnerability_intel_summary,
                "recon_plan_summary": self.recon_plan_summary,
                "tool_capability_summary": self.tool_capability_summary,
                "evidence_count": self.evidence_count,
                "finding_count": self.finding_count,
                "hypothesis_count": self.hypothesis_count,
                "report_paths": self.report_paths,
                "reports": self.reports,
                "audit_verification_status": self.audit_verification_status,
                "live_request_performed": self.live_request_performed,
                "no_body_stored": self.no_body_stored,
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "redaction_applied": self.redaction_applied,
                "metadata": self.metadata,
            }
        )


def run_portfolio_operator_pipeline(
    pipeline_input: PortfolioDemoInput,
    *,
    transport: Transport | None = None,
    knowledge_records: list[dict[str, Any]] | None = None,
) -> PortfolioOperatorPipelineResult:
    created = (pipeline_input.now or datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()
    now = pipeline_input.now or datetime(2026, 1, 1, tzinfo=timezone.utc)
    warnings: list[str] = []
    errors: list[str] = []
    store = ProjectWorkspaceStore()
    evidence_store = EvidenceStore()
    output_root = Path(pipeline_input.output_dir) if pipeline_input.output_dir else Path(tempfile.mkdtemp(prefix="aegis-operator-pipeline-"))
    audit_path = output_root / "operator_pipeline_audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    audit = AuditLog(audit_path)

    scope = ScopeDefinition(
        scope_id="scope_authorized_portfolio_operator_pipeline",
        allowlist_domains=(pipeline_input.allowed_domain,),
        allowlist_urls=(pipeline_input.target_url,),
        allowed_schemes=pipeline_input.allowed_schemes,
        environment=pipeline_input.environment,
        valid_from=created,
        valid_until="2027-01-01T00:00:00+00:00",
        owner_attestation="Owner authorization attestation provided in local input.",
        notes="Authorized portfolio operator pipeline. One safe metadata/header collection only.",
        tags=("authorized-portfolio-operator-pipeline",) + pipeline_input.tags,
    )
    authorization = scope.to_authorization_profile(owner=pipeline_input.owner_name or pipeline_input.project_name, now=pipeline_input.now)
    project = create_project_record(
        {
            "project_id": "project_authorized_portfolio_operator_pipeline",
            "name": pipeline_input.project_name,
            "description": "Authorized owner-provided portfolio operator pipeline.",
            "customer_name": pipeline_input.owner_name,
            "environment": pipeline_input.environment,
            "created_at_utc": created,
            "status": "active",
            "scope": scope.to_dict(),
            "tags": ["authorized-portfolio-operator-pipeline", "safe-mode", *pipeline_input.tags],
            "metadata": {"safe_mode": True, "no_body_capture": True, "operator_pipeline": True, **pipeline_input.metadata},
        }
    )
    store.create_project(project)
    _append_pipeline_audit(audit, "operator_pipeline_started", project.project_id, {"project_id": project.project_id}, created, 1)

    target = store.add_target(
        project.project_id,
        create_target_record(
            {
                "target_id": "target_authorized_portfolio_operator_pipeline",
                "target_type": "url",
                "value": pipeline_input.target_url,
                "display_name": "Authorized portfolio target",
                "created_at_utc": created,
                "tags": ["authorized-portfolio-operator-pipeline"],
            },
            project,
        ),
    )
    if not target.in_scope:
        _append_pipeline_audit(audit, "operator_pipeline_denied", pipeline_input.target_url, {"reason": target.scope_reason}, created, 2, allowed=False)
        raise ValueError(f"target is not in project scope: {target.scope_reason}")
    session = SessionRecord(
        session_id="session_authorized_portfolio_operator_pipeline",
        project_id=project.project_id,
        created_at_utc=created,
        updated_at_utc=created,
        actor="portfolio-owner",
        purpose="Run safe integrated portfolio operator pipeline.",
        status="completed",
        selected_targets=(target.target_id,),
        metadata={"safe_mode": True, "no_body_stored": True, "attestation": "owner_provided", "operator_pipeline": True},
    )
    store.create_session(session)

    fetch_request = SafeHttpFetchRequest(
        fetch_id="fetch_authorized_portfolio_operator_pipeline",
        target=target.normalized_value,
        authorization_profile=authorization,
        method="HEAD",
        requested_by=pipeline_input.owner_name or "portfolio-owner",
        actor="portfolio-owner",
        max_redirects=pipeline_input.max_redirects,
        timeout_seconds=pipeline_input.timeout_seconds,
        now=now,
        metadata={"pipeline_id": PIPELINE_ID, "safe_mode": True},
    )
    fetch_result = safe_http_fetch(fetch_request, transport=transport, audit_log=audit)
    live_request_performed = transport is None and fetch_result.allowed
    fetch_evidence = None
    if fetch_result.allowed and not fetch_result.error:
        fetch_evidence = replace(evidence_from_fetch_result(fetch_result), evidence_id="evidence_operator_fetch", created_at_utc=created)
        _add_evidence(evidence_store, store, project.project_id, fetch_evidence)
    _append_pipeline_audit(audit, "safe_fetch_completed", target.normalized_value, {"status_code": fetch_result.status_code, "allowed": fetch_result.allowed}, created, 3)

    checks, header_evidence, findings = analyze_headers_from_fetch_result(fetch_result)
    header_check_dicts: list[dict[str, Any]] = []
    for index, check in enumerate(checks, start=1):
        check_dict = check.to_dict() if hasattr(check, "to_dict") else dict(check)
        evidence_id = f"evidence_operator_header_{index:03d}"
        check_dict["evidence_id"] = evidence_id
        header_check_dicts.append(check_dict)
        record = replace(header_evidence[index - 1], evidence_id=evidence_id, created_at_utc=created)
        _add_evidence(evidence_store, store, project.project_id, record)
    for index, finding in enumerate(findings, start=1):
        record = replace(
            finding,
            finding_id=f"finding_operator_header_{index:03d}",
            evidence_ids=(f"evidence_operator_header_{index:03d}",),
            created_at_utc=created,
            updated_at_utc=created,
        )
        evidence_store.add_finding(record)
        store.add_finding_reference(project.project_id, record.finding_id)
    _append_pipeline_audit(audit, "header_analysis_completed", target.normalized_value, {"check_count": len(checks), "finding_count": len(findings)}, created, 4)

    fingerprint = fingerprint_technology(
        TechnologyFingerprintInput(
            target=fetch_result.target,
            normalized_target=fetch_result.normalized_target,
            source_type="operator_pipeline_safe_fetch",
            headers=fetch_result.headers,
            final_url=fetch_result.final_url,
            redirect_chain=fetch_result.redirect_chain,
            content_type=fetch_result.content_type,
            content_length=fetch_result.content_length,
            evidence_ids=(fetch_evidence.evidence_id,) if fetch_evidence else (),
            created_at_utc=created,
            metadata={"pipeline_id": PIPELINE_ID, "no_body_stored": True},
        )
    )
    fingerprint_evidence = replace(evidence_from_fingerprint(fingerprint), evidence_id="evidence_operator_fingerprint", created_at_utc=created)
    _add_evidence(evidence_store, store, project.project_id, fingerprint_evidence)
    _append_pipeline_audit(audit, "fingerprint_completed", target.normalized_value, {"technology_count": len(fingerprint.detected_technologies)}, created, 5)

    graph = build_attack_surface_graph(
        {
            "created_at_utc": created,
            "project": store.get_project(project.project_id).to_dict(),
            "targets": [target.to_dict()],
            "fetch_result": fetch_result.to_dict() | {"evidence_ids": [fetch_evidence.evidence_id] if fetch_evidence else []},
            "header_checks": header_check_dicts,
            "technology_fingerprint": fingerprint.to_dict(),
            "risk_hypotheses": [item.to_dict() for item in fingerprint.risk_hypotheses],
            "evidence": [item.to_dict() for item in evidence_store.list_evidence()],
            "findings": [item.to_dict() for item in evidence_store.list_findings()],
            "environment": pipeline_input.environment,
        }
    )
    graph_evidence = replace(evidence_from_attack_surface_graph(graph), evidence_id="evidence_operator_attack_surface_graph", created_at_utc=created)
    _add_evidence(evidence_store, store, project.project_id, graph_evidence)
    _append_pipeline_audit(audit, "attack_surface_graph_completed", target.normalized_value, {"node_count": len(graph.nodes), "edge_count": len(graph.edges)}, created, 6)

    knowledge = knowledge_records if knowledge_records is not None else _default_knowledge_records()
    mapping = map_vulnerability_intelligence(
        {
            "created_at_utc": created,
            "environment": pipeline_input.environment,
            "attack_surface_graph": graph.to_dict(),
            "technology_fingerprint": fingerprint.to_dict(),
            "knowledge_records": knowledge,
            "evidence": [item.to_dict() for item in evidence_store.list_evidence()],
        }
    )
    mapping_evidence = replace(evidence_from_vulnerability_mapping(mapping), evidence_id="evidence_operator_vuln_intel", created_at_utc=created)
    _add_evidence(evidence_store, store, project.project_id, mapping_evidence)
    _append_pipeline_audit(audit, "vuln_intel_mapping_completed", target.normalized_value, {"match_count": mapping.match_count}, created, 7)

    recon = plan_safe_recon(
        {
            "created_at_utc": created,
            "target": target.normalized_value,
            "environment": pipeline_input.environment,
            "project": store.get_project(project.project_id).to_dict(),
            "fetch_result": fetch_result.to_dict(),
            "header_checks": header_check_dicts,
            "technology_fingerprint": fingerprint.to_dict(),
            "attack_surface_graph": graph.to_dict(),
            "vulnerability_mapping": mapping.to_dict(),
            "evidence": [item.to_dict() for item in evidence_store.list_evidence()],
            "findings": [item.to_dict() for item in evidence_store.list_findings()],
        },
        authorization_profile=authorization,
    )
    recon_evidence = replace(evidence_from_recon_plan(recon), evidence_id="evidence_operator_recon_plan", created_at_utc=created)
    _add_evidence(evidence_store, store, project.project_id, recon_evidence)
    _append_pipeline_audit(audit, "recon_plan_completed", target.normalized_value, {"step_count": len(recon.steps)}, created, 8)

    tool_plans = _tool_capability_suggestions(recon, target.normalized_value, authorization, created)
    for index, plan in enumerate(tool_plans, start=1):
        tool_evidence = replace(evidence_from_tool_plan(plan), evidence_id=f"evidence_operator_tool_plan_{index:03d}", created_at_utc=created)
        _add_evidence(evidence_store, store, project.project_id, tool_evidence)

    final_summary_evidence = EvidenceRecord(
        evidence_id="evidence_operator_pipeline_summary",
        created_at_utc=created,
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.ADAPTER,
        source_id=PIPELINE_ID,
        target=target.normalized_value,
        normalized_target=target.normalized_value,
        title="Integrated portfolio operator pipeline summary",
        summary="Safe operator pipeline completed with no crawler, scanner, fuzzer, external tool execution, or body storage.",
        structured_data={"pipeline_id": PIPELINE_ID, "no_body_stored": True, "external_tool_execution": False},
        tags=("operator-pipeline", "safe-mode", "no-external-tools"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )
    _add_evidence(evidence_store, store, project.project_id, final_summary_evidence)

    audit_verification = audit.verify()
    report = create_report(
        project_name=project.name,
        evidence_store=evidence_store,
        audit_verification=audit_verification,
        report_id="report_authorized_portfolio_operator_pipeline",
        created_at_utc=created,
        customer_name=project.customer_name,
        environment=project.environment,
        scope_summary=f"Authorized owner-provided operator pipeline scope includes only {pipeline_input.allowed_domain}.",
        authorization_summary="Owner authorization attestation was required and provided in local input. Safe mode remained enabled.",
        executive_summary=(
            "Authorized portfolio operator pipeline completed one low-impact metadata/header collection and local deterministic analysis. "
            "Observations are candidate, evidence-backed, or hypothesis-level only."
        ),
        methodology_summary=(
            "Policy-gated HEAD metadata request, header checks, passive fingerprinting, attack surface graph, offline knowledge mapping, "
            "safe recon planning, and green-tier dry-run capability suggestions. No body storage."
        ),
        limitations=[
            "Authorized owner-provided demo only.",
            "One safe metadata/header collection only.",
            "No crawling, fuzzing, brute force, scanner, external tool execution, asset fetching, live vulnerability feed access, HAR replay, Postman execution, or login/session capture was performed.",
            "Findings are candidate/evidence-backed observations, not confirmed exploitability.",
            "Fingerprinting and vulnerability intelligence matches are hypotheses and prioritization hints, not vulnerability confirmation.",
            "No response body, cookies, tokens, or raw auth material is stored.",
        ],
        generated_by="Aegis EV integrated portfolio operator pipeline",
        tags=("authorized-portfolio-operator-pipeline", "safe-mode", "no-body", "no-external-tools"),
    )
    sections = _operator_sections(fingerprint, graph, mapping, recon, tool_plans)
    markdown = render_report_markdown(report) + "\n" + _sections_markdown(sections)
    report_json = _report_json_with_sections(report, sections)
    store.add_report_reference(project.project_id, report.report_id)
    _append_pipeline_audit(audit, "report_generated", project.project_id, {"report_id": report.report_id}, created, 9)
    _append_pipeline_audit(audit, "operator_pipeline_completed", project.project_id, {"evidence_count": len(evidence_store.list_evidence())}, created, 10)
    audit_verification = audit.verify()

    report_paths: dict[str, str] = {}
    reports: dict[str, str] = {}
    if pipeline_input.write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        markdown_path = output_root / "portfolio_operator_pipeline_report.md"
        json_path = output_root / "portfolio_operator_pipeline_report.json"
        markdown_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(report_json + "\n", encoding="utf-8")
        report_paths = {"markdown": str(markdown_path), "json": str(json_path), "audit": str(audit_path)}
    if pipeline_input.include_report_contents:
        reports = {"markdown": markdown, "json": report_json}

    return PortfolioOperatorPipelineResult(
        pipeline_id=PIPELINE_ID,
        created_at_utc=created,
        project_id=project.project_id,
        session_id=session.session_id,
        target=pipeline_input.target_url,
        normalized_target=target.normalized_value,
        fetch_summary=_fetch_summary(fetch_result),
        header_check_summary={"check_count": len(checks), "candidate_finding_count": len(findings)},
        fingerprint_summary=_fingerprint_summary(fingerprint),
        attack_surface_summary=attack_surface_report_section(graph),
        vulnerability_intel_summary=vulnerability_intelligence_report_section(mapping),
        recon_plan_summary=recon_plan_report_section(recon),
        tool_capability_summary=_tool_summary(tool_plans),
        evidence_count=len(evidence_store.list_evidence()),
        finding_count=len(evidence_store.list_findings()),
        hypothesis_count=len(fingerprint.risk_hypotheses) + graph.hypothesis_count,
        report_paths=report_paths,
        reports=reports,
        audit_verification_status=_audit_status(audit_verification),
        live_request_performed=live_request_performed,
        no_body_stored=True,
        warnings=tuple(sorted(set(warnings + list(fetch_result.warnings) + list(fingerprint.warnings) + list(graph.warnings) + list(mapping.warnings) + list(recon.warnings)))),
        errors=tuple(errors),
        redaction_applied=True,
        metadata={"external_tool_execution": False, "crawler": False, "scanner": False, "fuzzer": False, "live_feed_access": False},
    )


def run_portfolio_operator_pipeline_from_payload(payload: dict[str, Any]) -> PortfolioOperatorPipelineResult:
    pipeline_input = PortfolioDemoInput.from_payload(payload)
    transport = fixture_transport(payload["transport_fixture"]) if payload.get("transport_fixture") else None
    return run_portfolio_operator_pipeline(pipeline_input, transport=transport)


def _tool_capability_suggestions(recon: Any, target: str, authorization: Any, created: str) -> tuple[Any, ...]:
    plans = []
    seen: set[tuple[str, str]] = set()
    for step in recon.steps:
        tool_id = step.metadata.get("tool_capability_id")
        if not tool_id or not step.adapter_action:
            continue
        key = (tool_id, step.adapter_action)
        if key in seen:
            continue
        seen.add(key)
        payload: dict[str, Any] = {"tool_id": tool_id, "action": step.adapter_action, "dry_run": True, "now": created}
        if tool_id == "builtin_safe_http_fetch":
            payload["target"] = target
        plans.append(plan_tool_action(payload, authorization_profile=authorization))
    for tool_id, action in (
        ("builtin_safe_http_fetch", "fetch_metadata"),
        ("builtin_safe_header_analysis", "analyze_headers"),
        ("builtin_passive_fingerprint", "fingerprint_from_metadata"),
        ("builtin_attack_surface_graph", "build_attack_surface_graph"),
        ("builtin_vuln_intel_mapping", "map_vulnerability_intelligence"),
    ):
        key = (tool_id, action)
        if key in seen:
            continue
        payload = {"tool_id": tool_id, "action": action, "dry_run": True, "now": created}
        if tool_id == "builtin_safe_http_fetch":
            payload["target"] = target
        plans.append(plan_tool_action(payload, authorization_profile=authorization))
    return tuple(plans)


def _operator_sections(fingerprint: Any, graph: Any, mapping: Any, recon: Any, tool_plans: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "technology_fingerprint_summary": _fingerprint_summary(fingerprint),
        "attack_surface_summary": attack_surface_report_section(graph),
        "vulnerability_intelligence_summary": vulnerability_intelligence_report_section(mapping),
        "safe_recon_plan": recon_plan_report_section(recon),
        "green_tier_tool_capability_suggestions": _tool_summary(tool_plans),
        "pipeline_limitations": [
            "Authorized owner-provided demo only.",
            "No crawling, fuzzing, scanning, external tool execution, live vulnerability feed access, or exploit validation was performed.",
            "No response body is stored.",
            "All findings remain candidate or hypothesis-level unless separately validated in a future approved workflow.",
        ],
    }


def _sections_markdown(sections: dict[str, Any]) -> str:
    lines = [
        "## Technology Fingerprint Summary",
        "",
        f"- Detected technology hints: {sections['technology_fingerprint_summary']['detected_technology_count']}",
        f"- Risk hypotheses: {sections['technology_fingerprint_summary']['risk_hypothesis_count']}",
        "",
        "## Attack Surface Summary",
        "",
        f"- Nodes: {sections['attack_surface_summary'].get('target_count', 0)} target-related, {sections['attack_surface_summary'].get('endpoint_count', 0)} endpoint, {sections['attack_surface_summary'].get('technology_count', 0)} technology.",
        f"- Missing controls: {', '.join(sections['attack_surface_summary'].get('missing_controls', [])) or 'none'}",
        "",
        "## Vulnerability Intelligence Summary",
        "",
        f"- Knowledge matches: {sections['vulnerability_intelligence_summary']['match_count']}",
        f"- Priority hints: {sections['vulnerability_intelligence_summary']['priority_hints'] or 'none'}",
        "",
        "## Safe Recon Plan",
        "",
        f"- Proposed steps: {sections['safe_recon_plan']['step_count']}",
        f"- Blocked steps: {sections['safe_recon_plan']['blocked_step_count']}",
        f"- Approval-required steps: {sections['safe_recon_plan']['approval_required_step_count']}",
        "",
        "## Green-Tier Tool Capability Suggestions",
        "",
    ]
    suggestions = sections["green_tier_tool_capability_suggestions"]["suggestions"]
    if not suggestions:
        lines.append("- No green-tier tool capability suggestions were produced.")
    for item in suggestions:
        lines.append(f"- `{item['tool_id']}` / `{item['action']}`: dry-run only, allowed={item['allowed']}")
    lines.extend(["", "## Pipeline Limitations", ""])
    lines.extend(f"- {item}" for item in sections["pipeline_limitations"])
    lines.append("")
    return "\n".join(lines)


def _report_json_with_sections(report: Any, sections: dict[str, Any]) -> str:
    data = json.loads(render_report_json(report))
    data["operator_pipeline_sections"] = redact_value(sections)
    return canonical_json(data)


def _fetch_summary(fetch_result: Any) -> dict[str, Any]:
    return {
        "allowed": fetch_result.allowed,
        "status_code": fetch_result.status_code,
        "method": fetch_result.method,
        "final_url": fetch_result.final_url,
        "error": fetch_result.error,
        "header_count": len(fetch_result.headers),
        "redaction_applied": fetch_result.redaction_applied,
        "no_body_stored": fetch_result.no_body_stored,
    }


def _fingerprint_summary(fingerprint: Any) -> dict[str, Any]:
    return {
        "fingerprint_id": fingerprint.fingerprint_id,
        "confidence": fingerprint.confidence,
        "detected_technology_count": len(fingerprint.detected_technologies),
        "detected_frameworks": list(fingerprint.detected_frameworks),
        "detected_platforms": list(fingerprint.detected_platforms),
        "detected_missing_controls": list(fingerprint.detected_missing_controls),
        "risk_hypothesis_count": len(fingerprint.risk_hypotheses),
    }


def _tool_summary(tool_plans: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "suggestion_count": len(tool_plans),
        "dry_run_only": True,
        "external_tool_execution": False,
        "suggestions": [
            {
                "tool_id": plan.tool_id,
                "action": plan.action,
                "allowed": plan.allowed,
                "required_approval": plan.required_approval,
                "argv_preview": list(plan.argv_preview),
                "errors": list(plan.errors),
                "warnings": list(plan.warnings),
            }
            for plan in tool_plans
        ],
    }


def _default_knowledge_records() -> list[dict[str, Any]]:
    root = Path(__file__).resolve().parents[3]
    records: list[dict[str, Any]] = []
    for path in (
        root / "fixtures" / "knowledge" / "owasp_web_baseline.json",
        root / "fixtures" / "knowledge" / "cwe_baseline.json",
        root / "fixtures" / "knowledge" / "vuln_intel_sample.json",
    ):
        payload = json.loads(path.read_text(encoding="utf-8"))
        records.extend(payload.get("records", []))
    return records


def _add_evidence(evidence_store: EvidenceStore, store: ProjectWorkspaceStore, project_id: str, evidence: EvidenceRecord) -> None:
    evidence_store.add_evidence(evidence)
    store.add_evidence_reference(project_id, evidence.evidence_id)


def _append_pipeline_audit(audit: AuditLog, action: str, target: str | None, metadata: dict[str, Any], timestamp: str, sequence: int, *, allowed: bool = True) -> None:
    audit.append(
        actor="portfolio-owner",
        action=action,
        target=target,
        details=metadata | {"pipeline_id": PIPELINE_ID, "safe_mode": True, "no_body_stored": True},
        event_type=action,
        allowed=allowed,
        required_approval=False,
        event_id=f"audit_operator_pipeline_{sequence:03d}_{action}",
        timestamp_utc=timestamp,
    )


def _audit_status(result: AuditVerificationResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "event_count": result.event_count,
        "last_hash": result.last_hash,
        "errors": list(result.errors),
    }
