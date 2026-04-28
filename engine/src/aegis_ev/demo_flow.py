from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog, AuditVerificationResult, canonical_json, redact_value
from .checks.web_headers import (
    WebHeaderAnalysisInput,
    analyze_web_headers,
    evidence_from_web_header_check,
    finding_from_web_header_check,
)
from .evidence import EvidenceStore
from .imports import evidence_from_import_result, import_har, import_openapi, import_postman
from .projects import (
    ProjectWorkspaceStore,
    ScopeDefinition,
    SessionRecord,
    create_project_record,
    create_target_record,
)
from .reporting import create_report, render_report_json, render_report_markdown


DEMO_ID = "demo_local_portfolio_placeholder_v1"
DEMO_CREATED_AT = "2026-01-01T00:00:00+00:00"
PLACEHOLDER_TARGET = "https://portfolio.example.test"
PLACEHOLDER_API_TARGET = "https://api.portfolio.example.test"


@dataclass(frozen=True)
class DemoFlowResult:
    demo_id: str
    project_id: str
    session_id: str
    target_count: int
    imported_endpoint_count: int
    evidence_count: int
    finding_count: int
    report_paths: dict[str, str] = field(default_factory=dict)
    reports: dict[str, str] = field(default_factory=dict)
    audit_verification_status: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    no_network: bool = True
    project: dict[str, Any] = field(default_factory=dict)
    session: dict[str, Any] = field(default_factory=dict)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    project_summary: dict[str, Any] = field(default_factory=dict)
    target_scope_summary: dict[str, Any] = field(default_factory=dict)
    pipeline_stage_summaries: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    evidence_summaries: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    finding_summaries: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    report_summaries: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    safety_flags: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "demo_id": self.demo_id,
                "project_id": self.project_id,
                "session_id": self.session_id,
                "target_count": self.target_count,
                "imported_endpoint_count": self.imported_endpoint_count,
                "evidence_count": self.evidence_count,
                "finding_count": self.finding_count,
                "report_paths": self.report_paths,
                "reports": self.reports,
                "audit_verification_status": self.audit_verification_status,
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "no_network": self.no_network,
                "project": self.project,
                "session": self.session,
                "evidence_ids": list(self.evidence_ids),
                "finding_ids": list(self.finding_ids),
                "project_summary": self.project_summary,
                "target_scope_summary": self.target_scope_summary,
                "pipeline_stage_summaries": list(self.pipeline_stage_summaries),
                "evidence_summaries": list(self.evidence_summaries),
                "finding_summaries": list(self.finding_summaries),
                "report_summaries": list(self.report_summaries),
                "safety_flags": self.safety_flags,
            }
        )


def run_demo_flow(
    *,
    fixture_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    write_outputs: bool = False,
    include_report_contents: bool = True,
    now: datetime | None = None,
) -> DemoFlowResult:
    timestamp = (now or datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()
    fixtures = Path(fixture_dir or _default_fixture_dir())
    warnings: list[str] = []
    errors: list[str] = []

    store = ProjectWorkspaceStore()
    evidence_store = EvidenceStore()
    project_scope = ScopeDefinition(
        scope_id="scope_demo_portfolio_placeholder",
        allowlist_domains=("portfolio.example.test", "api.portfolio.example.test"),
        allowlist_urls=(PLACEHOLDER_TARGET, PLACEHOLDER_API_TARGET),
        allowed_schemes=("https",),
        environment="staging",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_until="2026-12-31T00:00:00+00:00",
        owner_attestation="Future owner-authorized portfolio demo placeholder. No live request is performed.",
        tags=("demo", "portfolio-placeholder"),
    )
    project = create_project_record(
        {
            "project_id": "project_demo_portfolio_placeholder",
            "name": "Aegis EV Local Demo Project",
            "description": "Fixture-only local demo. No live validation or website contact.",
            "customer_name": "Portfolio Owner Placeholder",
            "environment": "staging",
            "created_at_utc": timestamp,
            "status": "active",
            "scope": project_scope.to_dict(),
            "tags": ["demo", "fixture-only"],
        }
    )
    store.create_project(project)
    target = store.add_target(
        project.project_id,
        create_target_record(
            {
                "target_id": "target_demo_portfolio_placeholder",
                "target_type": "url",
                "value": PLACEHOLDER_TARGET,
                "display_name": "Portfolio placeholder",
                "created_at_utc": timestamp,
                "tags": ["portfolio-placeholder"],
            },
            project,
        ),
    )
    api_target = store.add_target(
        project.project_id,
        create_target_record(
            {
                "target_id": "target_demo_api_placeholder",
                "target_type": "api",
                "value": PLACEHOLDER_API_TARGET,
                "display_name": "Portfolio API placeholder",
                "created_at_utc": timestamp,
                "tags": ["api", "portfolio-placeholder"],
            },
            project,
        ),
    )
    session = SessionRecord(
        session_id="session_demo_local_flow",
        project_id=project.project_id,
        created_at_utc=timestamp,
        updated_at_utc=timestamp,
        actor="codex-demo",
        purpose="Run deterministic local fixture demo without network access.",
        status="completed",
        selected_targets=(target.target_id, api_target.target_id),
        metadata={"mode": "fixture-only", "no_network": True},
    )
    store.create_session(session)

    audit_root = Path(output_dir) if output_dir is not None else Path(tempfile.mkdtemp(prefix="aegis-demo-flow-"))
    audit_path = audit_root / "audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    audit = AuditLog(audit_path)
    _append_demo_audit(audit, "project_created", project.project_id, {"project_id": project.project_id}, timestamp, 1)
    _append_demo_audit(audit, "target_added", target.normalized_value, {"target_id": target.target_id}, timestamp, 2)
    _append_demo_audit(audit, "target_added", api_target.normalized_value, {"target_id": api_target.target_id}, timestamp, 3)

    imported_endpoint_count = 0
    for source_name, filename, importer in (
        ("OpenAPI demo fixture", "demo_openapi.json", import_openapi),
        ("Postman demo fixture", "demo_postman_collection.json", import_postman),
        ("HAR demo fixture", "demo_har.json", import_har),
    ):
        path = fixtures / filename
        if not path.exists():
            warnings.append(f"Optional fixture not found: {filename}")
            continue
        result = importer(_read_json(path), source_name=source_name, now=now or datetime(2026, 1, 1, tzinfo=timezone.utc))
        warnings.extend(result.warnings)
        errors.extend(result.errors)
        imported_endpoint_count += result.endpoint_count
        evidence = evidence_from_import_result(result)
        evidence_store.add_evidence(evidence)
        store.add_import_reference(project.project_id, result.import_id)
        store.add_evidence_reference(project.project_id, evidence.evidence_id)
        _append_demo_audit(
            audit,
            "import_processed",
            project.project_id,
            {"source_type": result.source_type, "endpoint_count": result.endpoint_count, "import_id": result.import_id},
            timestamp,
            4 + imported_endpoint_count,
        )

    headers_fixture = _read_json(fixtures / "demo_headers.json")
    header_input = WebHeaderAnalysisInput(
        target=str(headers_fixture.get("target", PLACEHOLDER_TARGET)),
        status_code=headers_fixture.get("status_code"),
        headers=headers_fixture.get("headers", {}),
        content_type=headers_fixture.get("content_type"),
        protocol=headers_fixture.get("protocol"),
        source_reference="fixtures/demo/demo_headers.json",
        security_txt_present=headers_fixture.get("security_txt_present"),
    )
    header_results = analyze_web_headers(header_input)
    _append_demo_audit(audit, "header_check_processed", header_input.target, {"check_count": len(header_results)}, timestamp, 20)
    for result in header_results:
        evidence = replace(
            evidence_from_web_header_check(result),
            evidence_id=f"evidence_demo_header_{result.check_id}",
            created_at_utc=timestamp,
        )
        evidence_store.add_evidence(evidence)
        store.add_evidence_reference(project.project_id, evidence.evidence_id)
        if result.finding_candidate:
            finding = replace(
                finding_from_web_header_check(result, evidence),
                finding_id=f"finding_demo_header_{result.check_id}",
                created_at_utc=timestamp,
                updated_at_utc=timestamp,
            )
            evidence_store.add_finding(finding)
            store.add_finding_reference(project.project_id, finding.finding_id)

    audit_verification = audit.verify()
    report = create_report(
        project_name=project.name,
        evidence_store=evidence_store,
        audit_verification=audit_verification,
        report_id="report_demo_local_flow",
        created_at_utc=timestamp,
        customer_name=project.customer_name,
        environment=project.environment,
        scope_summary="Demo fixture scope includes only portfolio.example.test and api.portfolio.example.test placeholders.",
        authorization_summary="Owner-authorized future portfolio demo is modeled with placeholders only; no live request was made.",
        executive_summary="Demo mode: deterministic local fixture pipeline completed. This report does not prove live exposure or exploitability.",
        methodology_summary="Fixture-only import and supplied-header analysis. No network, crawling, scanning, HAR replay, Postman execution, or AI verification.",
        limitations=[
            "Demo/fixture mode only.",
            "No live validation was performed.",
            "Findings are candidate/evidence-backed observations, not confirmed exploitability.",
        ],
        generated_by="Aegis EV local demo flow",
        tags=("demo", "fixture-only", "no-network"),
    )
    markdown = render_report_markdown(report)
    report_json = render_report_json(report)
    _append_demo_audit(audit, "report_generated", project.project_id, {"report_id": report.report_id}, timestamp, 21)
    audit_verification = audit.verify()

    report_paths: dict[str, str] = {}
    reports: dict[str, str] = {}
    if write_outputs:
        target_dir = Path(output_dir or "output/demo")
        target_dir.mkdir(parents=True, exist_ok=True)
        markdown_path = target_dir / "demo_report.md"
        json_path = target_dir / "demo_report.json"
        markdown_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(report_json + "\n", encoding="utf-8")
        report_paths = {"markdown": str(markdown_path), "json": str(json_path), "audit": str(audit_path)}
    if include_report_contents:
        reports = {"markdown": markdown, "json": report_json}

    final_project = store.get_project(project.project_id)
    final_session = store.get_session(session.session_id)
    evidence_records = evidence_store.list_evidence()
    finding_records = evidence_store.list_findings()
    report_summaries = (
        {
            "title": "Local Demo Markdown Report",
            "format": "markdown",
            "status": "generated" if markdown else "not_generated",
            "path": report_paths.get("markdown"),
            "summary": "Evidence-backed fixture report; no live target request.",
        },
        {
            "title": "Local Demo JSON Report",
            "format": "json",
            "status": "generated" if report_json else "not_generated",
            "path": report_paths.get("json"),
            "summary": "Structured fixture report data; no raw bodies or secrets.",
        },
        {
            "title": "Local Demo Audit Chain",
            "format": "jsonl",
            "status": "valid" if audit_verification.valid else "invalid",
            "path": report_paths.get("audit"),
            "summary": f"{audit_verification.event_count} audit events verified.",
        },
    )
    return DemoFlowResult(
        demo_id=DEMO_ID,
        project_id=project.project_id,
        session_id=session.session_id,
        target_count=len(final_project.targets),
        imported_endpoint_count=imported_endpoint_count,
        evidence_count=len(evidence_records),
        finding_count=len(finding_records),
        report_paths=report_paths,
        reports=reports,
        audit_verification_status=_audit_status(audit_verification),
        warnings=tuple(warnings),
        errors=tuple(errors),
        no_network=True,
        project=final_project.to_dict(),
        session=final_session.to_dict(),
        evidence_ids=tuple(record.evidence_id for record in evidence_records),
        finding_ids=tuple(record.finding_id for record in finding_records),
        project_summary={
            "project_name": final_project.name,
            "target_url": PLACEHOLDER_TARGET,
            "environment": final_project.environment,
            "safe_mode": True,
            "authorization": "placeholder-owner-attested",
            "pipeline_status": "completed",
            "evidence_count": len(evidence_records),
            "finding_count": len(finding_records),
            "audit_status": "valid" if audit_verification.valid else "invalid",
        },
        target_scope_summary={
            "allowed_domains": list(final_project.scope.allowlist_domains if final_project.scope else ()),
            "allowed_schemes": list(final_project.scope.allowed_schemes if final_project.scope else ()),
            "environment": final_project.environment,
            "authorization_attestation": "Placeholder owner-attestation model; no live request was made.",
            "target_count": len(final_project.targets),
        },
        pipeline_stage_summaries=(
            {"id": "project_scope_created", "name": "Project and scope created", "status": "completed", "evidence_count": 0, "warnings": []},
            {"id": "imports_processed", "name": "Fixture imports processed", "status": "completed", "evidence_count": 3, "warnings": warnings},
            {"id": "header_checks", "name": "Supplied header checks", "status": "completed", "evidence_count": len([item for item in evidence_records if str(item.source_type.value if hasattr(item.source_type, "value") else item.source_type) == "web_header_check"]), "warnings": []},
            {"id": "evidence_generated", "name": "Evidence generated", "status": "completed", "evidence_count": len(evidence_records), "warnings": []},
            {"id": "findings_generated", "name": "Candidate findings generated", "status": "completed", "evidence_count": len(finding_records), "warnings": ["Findings are candidate observations only."]},
            {"id": "report_generated", "name": "Markdown and JSON report generated", "status": "completed", "evidence_count": len(evidence_records), "warnings": []},
            {"id": "audit_verified", "name": "Audit chain verified", "status": "completed" if audit_verification.valid else "warning", "evidence_count": audit_verification.event_count, "warnings": list(audit_verification.errors)},
        ),
        evidence_summaries=tuple(
            {
                "id": record.evidence_id,
                "source_type": str(record.source_type.value if hasattr(record.source_type, "value") else record.source_type),
                "title": record.title,
                "summary": record.summary,
                "redaction_applied": True,
                "body_stored": False,
            }
            for record in evidence_records
        ),
        finding_summaries=tuple(
            {
                "id": record.finding_id,
                "title": record.title,
                "severity": str(record.severity.value if hasattr(record.severity, "value") else record.severity),
                "status": str(record.status.value if hasattr(record.status, "value") else record.status),
                "verification": str(record.verification_state.value if hasattr(record.verification_state, "value") else record.verification_state),
                "retest_status": str(record.retest_status.value if hasattr(record.retest_status, "value") else record.retest_status),
                "evidence_ids": list(record.evidence_ids),
            }
            for record in finding_records
        ),
        report_summaries=report_summaries,
        safety_flags={
            "executed_live_network": False,
            "executed_external_tool": False,
            "executed_scanner": False,
            "executed_crawler": False,
            "executed_fuzzer": False,
            "called_model_provider": False,
            "required_provider_credential": False,
            "stored_raw_body": False,
        },
    )


def run_demo_flow_from_payload(payload: dict[str, Any]) -> DemoFlowResult:
    if payload.get("no_network") is False:
        raise ValueError("demo flow is no-network only")
    fixture_dir = payload.get("fixture_dir")
    output_dir = payload.get("output_dir")
    write_outputs = bool(payload.get("write_outputs", False))
    include_report_contents = bool(payload.get("include_report_contents", True))
    now = None
    if payload.get("now"):
        now = datetime.fromisoformat(str(payload["now"]).replace("Z", "+00:00"))
    return run_demo_flow(
        fixture_dir=fixture_dir,
        output_dir=output_dir,
        write_outputs=write_outputs,
        include_report_contents=include_report_contents,
        now=now,
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Could not read demo fixture: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid demo fixture JSON: {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Demo fixture must be a JSON object: {path}")
    return payload


def _append_demo_audit(audit: AuditLog, action: str, target: str | None, metadata: dict[str, Any], timestamp: str, sequence: int) -> None:
    audit.append(
        actor="aegis-demo",
        action=action,
        target=target,
        details=metadata | {"demo_id": DEMO_ID, "no_network": True},
        event_type="demo_flow",
        allowed=True,
        required_approval=False,
        event_id=f"audit_demo_{sequence:03d}_{action}",
        timestamp_utc=timestamp,
    )


def _audit_status(result: AuditVerificationResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "event_count": result.event_count,
        "last_hash": result.last_hash,
        "errors": list(result.errors),
    }


def _default_fixture_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "fixtures" / "demo"
