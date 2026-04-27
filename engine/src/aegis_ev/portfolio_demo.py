from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .audit import AuditLog, AuditVerificationResult, redact_target, redact_value
from .evidence import EvidenceStore
from .http_fetch import (
    SafeHttpFetchRequest,
    Transport,
    analyze_headers_from_fetch_result,
    evidence_from_fetch_result,
    fixture_transport,
    safe_http_fetch,
)
from .projects import (
    ProjectWorkspaceStore,
    ScopeDefinition,
    SessionRecord,
    create_project_record,
    create_target_record,
    normalize_target_value,
)
from .reporting import create_report, render_report_json, render_report_markdown


PORTFOLIO_DEMO_ID = "authorized_portfolio_demo_v1"
DEFAULT_CREATED_AT = "2026-01-01T00:00:00+00:00"
DEFAULT_ALLOWED_SCHEMES = ("https",)


@dataclass(frozen=True)
class PortfolioDemoInput:
    project_name: str
    target_url: str
    owner_authorization_attestation: bool
    owner_name: str | None = None
    environment: str = "staging"
    safe_mode: bool = True
    allowed_domain: str = ""
    allowed_schemes: tuple[str, ...] = DEFAULT_ALLOWED_SCHEMES
    max_redirects: int = 3
    timeout_seconds: int = 5
    output_dir: str | None = None
    write_outputs: bool = False
    include_report_contents: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
    now: datetime | None = None

    def __post_init__(self) -> None:
        if not str(self.project_name).strip():
            raise ValueError("project_name is required")
        if self.owner_authorization_attestation is not True:
            raise ValueError("owner_authorization_attestation must be true")
        if self.safe_mode is not True:
            raise ValueError("safe_mode must be true")
        normalized = normalize_target_value("url", self.target_url)
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("target_url must use http or https")
        schemes = tuple(str(scheme).lower() for scheme in self.allowed_schemes if str(scheme).strip())
        if not schemes:
            raise ValueError("allowed_schemes must not be empty")
        for scheme in schemes:
            if scheme not in {"http", "https"}:
                raise ValueError(f"unsupported scheme: {scheme}")
        if parsed.scheme not in schemes:
            raise ValueError("target_url scheme is not allowed by scope")
        domain = _normalize_domain(self.allowed_domain or parsed.hostname or "")
        if parsed.hostname != domain:
            raise ValueError("target_url host must match allowed_domain")
        if self.max_redirects < 0 or self.max_redirects > 3:
            raise ValueError("max_redirects must be between 0 and 3")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 10:
            raise ValueError("timeout_seconds must be between 1 and 10")
        object.__setattr__(self, "target_url", normalized)
        object.__setattr__(self, "allowed_domain", domain)
        object.__setattr__(self, "allowed_schemes", schemes)
        object.__setattr__(self, "project_name", str(redact_value(self.project_name)).strip())
        object.__setattr__(self, "owner_name", redact_value(self.owner_name))
        object.__setattr__(self, "tags", tuple(sorted({str(tag) for tag in self.tags})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> PortfolioDemoInput:
        _reject_secret_fields(payload)
        if "transport_fixture" in payload and not isinstance(payload["transport_fixture"], dict):
            raise ValueError("transport_fixture must be an object")
        now = None
        if payload.get("now"):
            now = datetime.fromisoformat(str(payload["now"]).replace("Z", "+00:00"))
        return cls(
            project_name=str(_required(payload, "project_name")),
            target_url=str(_required(payload, "target_url")),
            owner_authorization_attestation=_required_bool(payload, "owner_authorization_attestation"),
            owner_name=payload.get("owner_name"),
            environment=str(payload.get("environment", "staging")),
            safe_mode=_required_bool(payload, "safe_mode"),
            allowed_domain=str(_required(payload, "allowed_domain")),
            allowed_schemes=tuple(payload.get("allowed_schemes", DEFAULT_ALLOWED_SCHEMES)),
            max_redirects=int(payload.get("max_redirects", 3)),
            timeout_seconds=int(payload.get("timeout_seconds", 5)),
            output_dir=payload.get("output_dir"),
            write_outputs=_optional_bool(payload, "write_outputs", bool(payload.get("output_dir"))),
            include_report_contents=_optional_bool(payload, "include_report_contents", not payload.get("output_dir")),
            tags=tuple(payload.get("tags", [])),
            metadata=payload.get("metadata", {}),
            now=now,
        )

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "project_name": self.project_name,
                "target_url": redact_target(self.target_url),
                "owner_authorization_attestation": self.owner_authorization_attestation,
                "owner_name": self.owner_name,
                "environment": self.environment,
                "safe_mode": self.safe_mode,
                "allowed_domain": self.allowed_domain,
                "allowed_schemes": list(self.allowed_schemes),
                "max_redirects": self.max_redirects,
                "timeout_seconds": self.timeout_seconds,
                "output_dir": self.output_dir,
                "write_outputs": self.write_outputs,
                "include_report_contents": self.include_report_contents,
                "tags": list(self.tags),
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True)
class PortfolioDemoResult:
    demo_id: str
    project_id: str | None
    session_id: str | None
    target_url: str
    normalized_target: str | None
    fetch_status: dict[str, Any]
    header_check_count: int
    evidence_count: int
    finding_count: int
    report_paths: dict[str, str] = field(default_factory=dict)
    reports: dict[str, str] = field(default_factory=dict)
    audit_verification_status: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    live_request_performed: bool = False
    no_body_stored: bool = True
    project: dict[str, Any] = field(default_factory=dict)
    session: dict[str, Any] = field(default_factory=dict)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "demo_id": self.demo_id,
                "project_id": self.project_id,
                "session_id": self.session_id,
                "target_url": redact_target(self.target_url),
                "normalized_target": redact_target(self.normalized_target),
                "fetch_status": self.fetch_status,
                "header_check_count": self.header_check_count,
                "evidence_count": self.evidence_count,
                "finding_count": self.finding_count,
                "report_paths": self.report_paths,
                "reports": self.reports,
                "audit_verification_status": self.audit_verification_status,
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "live_request_performed": self.live_request_performed,
                "no_body_stored": self.no_body_stored,
                "project": self.project,
                "session": self.session,
                "evidence_ids": list(self.evidence_ids),
                "finding_ids": list(self.finding_ids),
            }
        )


def run_portfolio_demo(
    demo_input: PortfolioDemoInput,
    *,
    transport: Transport | None = None,
) -> PortfolioDemoResult:
    timestamp = (demo_input.now or datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()
    warnings: list[str] = []
    errors: list[str] = []
    store = ProjectWorkspaceStore()
    evidence_store = EvidenceStore()
    output_root = Path(demo_input.output_dir) if demo_input.output_dir else Path(tempfile.mkdtemp(prefix="aegis-portfolio-demo-"))
    audit_path = output_root / "audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    audit = AuditLog(audit_path)

    scope = ScopeDefinition(
        scope_id="scope_authorized_portfolio_demo",
        allowlist_domains=(demo_input.allowed_domain,),
        allowlist_urls=(demo_input.target_url,),
        allowed_schemes=demo_input.allowed_schemes,
        environment=demo_input.environment,
        valid_from=timestamp,
        valid_until="2027-01-01T00:00:00+00:00",
        owner_attestation="Owner authorization attestation provided in local input.",
        notes="Authorized portfolio demo harness. Single target metadata/header check only.",
        tags=("authorized-portfolio-demo",) + demo_input.tags,
    )
    authorization = scope.to_authorization_profile(owner=demo_input.owner_name or demo_input.project_name, now=demo_input.now)
    project = create_project_record(
        {
            "project_id": "project_authorized_portfolio_demo",
            "name": demo_input.project_name,
            "description": "Authorized owner-provided portfolio demo harness.",
            "customer_name": demo_input.owner_name,
            "environment": demo_input.environment,
            "created_at_utc": timestamp,
            "status": "active",
            "scope": scope.to_dict(),
            "tags": ["authorized-portfolio-demo", "safe-mode", *demo_input.tags],
            "metadata": {"safe_mode": True, "no_body_capture": True, **demo_input.metadata},
        }
    )
    store.create_project(project)
    _append_portfolio_audit(audit, "portfolio_demo_project_created", project.project_id, {"project_id": project.project_id}, timestamp, 1)

    target = store.add_target(
        project.project_id,
        create_target_record(
            {
                "target_id": "target_authorized_portfolio_demo",
                "target_type": "url",
                "value": demo_input.target_url,
                "display_name": "Authorized portfolio target",
                "created_at_utc": timestamp,
                "tags": ["authorized-portfolio-demo"],
            },
            project,
        ),
    )
    _append_portfolio_audit(audit, "portfolio_demo_target_added", target.normalized_value, {"target_id": target.target_id}, timestamp, 2)
    if not target.in_scope:
        raise ValueError(f"target is not in project scope: {target.scope_reason}")

    session = SessionRecord(
        session_id="session_authorized_portfolio_demo",
        project_id=project.project_id,
        created_at_utc=timestamp,
        updated_at_utc=timestamp,
        actor="portfolio-owner",
        purpose="Run one authorized, safe-mode portfolio metadata/header analysis.",
        status="completed",
        selected_targets=(target.target_id,),
        metadata={"safe_mode": True, "no_body_stored": True, "attestation": "owner_provided"},
    )
    store.create_session(session)
    _append_portfolio_audit(audit, "portfolio_demo_session_created", session.session_id, {"session_id": session.session_id}, timestamp, 3)

    fetch_request = SafeHttpFetchRequest(
        fetch_id="fetch_authorized_portfolio_demo",
        target=target.normalized_value,
        authorization_profile=authorization,
        method="HEAD",
        requested_by=demo_input.owner_name or "portfolio-owner",
        actor="portfolio-owner",
        max_redirects=demo_input.max_redirects,
        timeout_seconds=demo_input.timeout_seconds,
        now=demo_input.now or datetime(2026, 1, 1, tzinfo=timezone.utc),
        metadata={"demo_id": PORTFOLIO_DEMO_ID, "safe_mode": True},
    )
    fetch_result = safe_http_fetch(fetch_request, transport=transport, audit_log=audit)
    live_request_performed = transport is None and fetch_result.allowed
    fetch_evidence = None
    if fetch_result.allowed and not fetch_result.error:
        fetch_evidence = replace(
            evidence_from_fetch_result(fetch_result),
            evidence_id="evidence_authorized_portfolio_fetch",
            created_at_utc=timestamp,
        )
        evidence_store.add_evidence(fetch_evidence)
        store.add_evidence_reference(project.project_id, fetch_evidence.evidence_id)
    checks, header_evidence, findings = analyze_headers_from_fetch_result(fetch_result)
    _append_portfolio_audit(
        audit,
        "portfolio_demo_header_analysis_completed",
        target.normalized_value,
        {"check_count": len(checks), "finding_count": len(findings)},
        timestamp,
        4,
    )
    for index, evidence in enumerate(header_evidence, start=1):
        record = replace(evidence, evidence_id=f"evidence_authorized_portfolio_header_{index:03d}", created_at_utc=timestamp)
        evidence_store.add_evidence(record)
        store.add_evidence_reference(project.project_id, record.evidence_id)
    for index, finding in enumerate(findings, start=1):
        evidence_ids = tuple(f"evidence_authorized_portfolio_header_{index:03d}" for _item in (finding,))
        record = replace(
            finding,
            finding_id=f"finding_authorized_portfolio_header_{index:03d}",
            evidence_ids=evidence_ids,
            created_at_utc=timestamp,
            updated_at_utc=timestamp,
        )
        evidence_store.add_finding(record)
        store.add_finding_reference(project.project_id, record.finding_id)

    audit_verification = audit.verify()
    report = create_report(
        project_name=project.name,
        evidence_store=evidence_store,
        audit_verification=audit_verification,
        report_id="report_authorized_portfolio_demo",
        created_at_utc=timestamp,
        customer_name=project.customer_name,
        environment=project.environment,
        scope_summary=f"Authorized owner-provided demo scope includes only {demo_input.allowed_domain}.",
        authorization_summary="Owner authorization attestation was required and provided in local input. Safe mode remained enabled.",
        executive_summary="Authorized portfolio demo completed one low-impact metadata/header analysis. This is not crawling, fuzzing, scanning, or exploit confirmation.",
        methodology_summary="Single policy-gated HEAD metadata request, strict redirect and timeout controls, no body storage, header analysis only.",
        limitations=[
            "Authorized owner-provided demo only.",
            "No crawling, fuzzing, brute force, scanner, HAR replay, Postman execution, or login/session capture was performed.",
            "Findings are candidate/evidence-backed observations, not confirmed exploitability.",
            "No response body, cookies, tokens, or raw auth material is stored.",
        ],
        generated_by="Aegis EV authorized portfolio demo harness",
        tags=("authorized-portfolio-demo", "safe-mode", "no-body"),
    )
    markdown = render_report_markdown(report)
    report_json = render_report_json(report)
    store.add_report_reference(project.project_id, report.report_id)
    _append_portfolio_audit(audit, "portfolio_demo_report_generated", project.project_id, {"report_id": report.report_id}, timestamp, 5)
    audit_verification = audit.verify()

    report_paths: dict[str, str] = {}
    reports: dict[str, str] = {}
    if demo_input.write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        markdown_path = output_root / "portfolio_demo_report.md"
        json_path = output_root / "portfolio_demo_report.json"
        markdown_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(report_json + "\n", encoding="utf-8")
        report_paths = {"markdown": str(markdown_path), "json": str(json_path), "audit": str(audit_path)}
    if demo_input.include_report_contents:
        reports = {"markdown": markdown, "json": report_json}

    final_project = store.get_project(project.project_id)
    final_session = store.get_session(session.session_id)
    fetch_status = {
        "allowed": fetch_result.allowed,
        "status_code": fetch_result.status_code,
        "error": fetch_result.error,
        "method": fetch_result.method,
        "final_url": fetch_result.final_url,
        "redaction_applied": fetch_result.redaction_applied,
        "no_body_stored": fetch_result.no_body_stored,
        "warnings": list(fetch_result.warnings),
    }
    return PortfolioDemoResult(
        demo_id=PORTFOLIO_DEMO_ID,
        project_id=project.project_id,
        session_id=session.session_id,
        target_url=demo_input.target_url,
        normalized_target=target.normalized_value,
        fetch_status=fetch_status,
        header_check_count=len(checks),
        evidence_count=len(evidence_store.list_evidence()),
        finding_count=len(evidence_store.list_findings()),
        report_paths=report_paths,
        reports=reports,
        audit_verification_status=_audit_status(audit_verification),
        warnings=tuple(warnings + list(fetch_result.warnings)),
        errors=tuple(errors),
        live_request_performed=live_request_performed,
        no_body_stored=True,
        project=final_project.to_dict(),
        session=final_session.to_dict(),
        evidence_ids=tuple(record.evidence_id for record in evidence_store.list_evidence()),
        finding_ids=tuple(record.finding_id for record in evidence_store.list_findings()),
    )


def run_portfolio_demo_from_payload(payload: dict[str, Any]) -> PortfolioDemoResult:
    demo_input = PortfolioDemoInput.from_payload(payload)
    transport = fixture_transport(payload["transport_fixture"]) if payload.get("transport_fixture") else None
    return run_portfolio_demo(demo_input, transport=transport)


def _required(payload: dict[str, Any], key: str) -> Any:
    if key not in payload:
        raise ValueError(f"Missing required field: {key}")
    return payload[key]


def _required_bool(payload: dict[str, Any], key: str) -> bool:
    value = _required(payload, key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _optional_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _reject_secret_fields(payload: dict[str, Any]) -> None:
    forbidden = {
        "headers",
        "authorization",
        "authorization_header",
        "auth_headers",
        "request_headers",
        "cookie",
        "cookies",
        "set_cookie",
        "set-cookie",
        "token",
        "api_key",
        "password",
        "body",
        "body_capture",
    }
    for key in payload:
        if str(key).lower() in forbidden:
            raise ValueError(f"{key} is not accepted by the portfolio demo harness")


def _normalize_domain(value: str) -> str:
    domain = str(value).strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or " " in domain:
        raise ValueError("allowed_domain must be a bare domain")
    return domain


def _append_portfolio_audit(audit: AuditLog, action: str, target: str | None, metadata: dict[str, Any], timestamp: str, sequence: int) -> None:
    audit.append(
        actor="portfolio-owner",
        action=action,
        target=target,
        details=metadata | {"demo_id": PORTFOLIO_DEMO_ID, "safe_mode": True, "no_body_stored": True},
        event_type="portfolio_demo",
        allowed=True,
        required_approval=False,
        event_id=f"audit_portfolio_demo_{sequence:03d}_{action}",
        timestamp_utc=timestamp,
    )


def _audit_status(result: AuditVerificationResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "event_count": result.event_count,
        "last_hash": result.last_hash,
        "errors": list(result.errors),
    }


def load_portfolio_demo_input(path: str | Path) -> PortfolioDemoInput:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("portfolio demo input must be a JSON object")
    return PortfolioDemoInput.from_payload(payload)
