from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from .audit import AuditVerificationResult, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceStore, FindingRecord


REPORT_SCHEMA_VERSION = "report.v1"
INLINE_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|password|passwd|pwd|secret|session|token)\b\s*[:= ]\s*[^\s,;]+"
)
INLINE_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


@dataclass(frozen=True)
class FindingReportSection:
    finding_id: str
    title: str
    severity: str
    confidence: str
    status: str
    verification_state: str
    target: str | None
    normalized_target: str | None
    category: str
    cwe_id: str | None
    owasp_reference: str | None
    cvss_score: float | None
    evidence_ids: tuple[str, ...]
    remediation: str
    retest_status: str
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_finding(cls, finding: FindingRecord) -> FindingReportSection:
        return cls(
            finding_id=finding.finding_id,
            title=_safe_text(finding.title),
            severity=str(finding.severity),
            confidence=str(finding.confidence),
            status=str(finding.status),
            verification_state=str(finding.verification_state),
            target=redact_target(finding.target),
            normalized_target=redact_target(finding.normalized_target),
            category=_safe_text(finding.category),
            cwe_id=_safe_text(finding.cwe_id),
            owasp_reference=_safe_text(finding.owasp_reference),
            cvss_score=finding.cvss_score,
            evidence_ids=tuple(sorted(finding.evidence_ids)),
            remediation=_safe_text(finding.remediation),
            retest_status=str(finding.retest_status),
            tags=tuple(sorted(set(finding.tags))),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceReportSection:
    evidence_id: str
    evidence_type: str
    source_type: str
    target: str | None
    normalized_target: str | None
    title: str
    summary: str
    related_audit_event_id: str | None
    related_adapter_id: str | None
    confidence: str
    redaction_applied: bool
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_evidence(cls, evidence: EvidenceRecord) -> EvidenceReportSection:
        data = evidence.to_dict()
        return cls(
            evidence_id=data["evidence_id"],
            evidence_type=data["evidence_type"],
            source_type=data["source_type"],
            target=redact_target(data["target"]),
            normalized_target=redact_target(data["normalized_target"]),
            title=_safe_text(data["title"]),
            summary=_safe_text(data["summary"]),
            related_audit_event_id=data["related_audit_event_id"],
            related_adapter_id=data["related_adapter_id"],
            confidence=data["confidence"],
            redaction_applied=bool(data["redaction_applied"]),
            tags=tuple(sorted(set(data["tags"]))),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditSummary:
    total_events: int | None = None
    verification_valid: bool | None = None
    hash_chain_status: str = "not_provided"
    latest_event_hash: str | None = None
    warning: str = "Audit verification was not provided. Tamper-evident logging is not tamper-proof storage."
    errors: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_verification(cls, result: AuditVerificationResult | None) -> AuditSummary:
        if result is None:
            return cls()
        valid = bool(result.valid)
        return cls(
            total_events=result.event_count,
            verification_valid=valid,
            hash_chain_status="valid" if valid else "failed",
            latest_event_hash=result.last_hash,
            warning=(
                "Audit hash chain verified. Tamper-evident logging is not tamper-proof storage."
                if valid
                else "Audit verification failed. Treat report audit metadata as incomplete until reviewed."
            ),
            errors=tuple(redact_value(result.errors)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskSummary:
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_verification_state: dict[str, int] = field(default_factory=dict)
    by_target: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0

    @classmethod
    def from_findings(cls, findings: list[FindingReportSection]) -> RiskSummary:
        return cls(
            by_severity=_count_by(findings, "severity"),
            by_status=_count_by(findings, "status"),
            by_verification_state=_count_by(findings, "verification_state"),
            by_target=_count_by(findings, "normalized_target"),
            by_category=_count_by(findings, "category"),
            total_findings=len(findings),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReportRecord:
    report_id: str = field(default_factory=lambda: f"report_{uuid4().hex}")
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    project_name: str = ""
    customer_name: str | None = None
    environment: str = "development"
    scope_summary: str = ""
    authorization_summary: str = ""
    executive_summary: str = ""
    methodology_summary: str = ""
    findings: tuple[FindingReportSection, ...] = field(default_factory=tuple)
    evidence_summary: tuple[EvidenceReportSection, ...] = field(default_factory=tuple)
    audit_summary: AuditSummary = field(default_factory=AuditSummary)
    risk_summary: RiskSummary = field(default_factory=RiskSummary)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    generated_by: str = "Aegis EV"
    report_version: str = REPORT_SCHEMA_VERSION
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not str(self.report_id).strip():
            raise ValueError("report_id is required")
        if not str(self.project_name).strip():
            raise ValueError("project_name is required")
        findings = tuple(sorted(self.findings, key=lambda item: item.finding_id))
        evidence = tuple(sorted(self.evidence_summary, key=lambda item: item.evidence_id))
        risk = self.risk_summary
        if risk.total_findings == 0 and findings:
            risk = RiskSummary.from_findings(list(findings))
        object.__setattr__(self, "project_name", _safe_text(self.project_name))
        object.__setattr__(self, "customer_name", _safe_text(self.customer_name))
        object.__setattr__(self, "environment", _safe_text(self.environment))
        object.__setattr__(self, "scope_summary", _safe_text(self.scope_summary))
        object.__setattr__(self, "authorization_summary", _safe_text(self.authorization_summary))
        object.__setattr__(self, "executive_summary", _safe_text(self.executive_summary))
        object.__setattr__(self, "methodology_summary", _safe_text(self.methodology_summary))
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "evidence_summary", evidence)
        object.__setattr__(self, "audit_summary", self.audit_summary)
        object.__setattr__(self, "risk_summary", risk)
        object.__setattr__(self, "limitations", tuple(_safe_text(item) for item in self.limitations))
        object.__setattr__(self, "generated_by", _safe_text(self.generated_by))
        object.__setattr__(self, "tags", tuple(sorted(set(_safe_text(item) for item in self.tags))))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.report_version,
            "report_id": self.report_id,
            "created_at_utc": self.created_at_utc,
            "project_name": self.project_name,
            "customer_name": self.customer_name,
            "environment": self.environment,
            "scope_summary": self.scope_summary,
            "authorization_summary": self.authorization_summary,
            "executive_summary": self.executive_summary,
            "methodology_summary": self.methodology_summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence_summary": [evidence.to_dict() for evidence in self.evidence_summary],
            "audit_summary": self.audit_summary.to_dict(),
            "risk_summary": self.risk_summary.to_dict(),
            "limitations": list(self.limitations),
            "generated_by": self.generated_by,
            "report_version": self.report_version,
            "tags": list(self.tags),
        }


def create_report(
    *,
    project_name: str,
    evidence_store: EvidenceStore | None = None,
    findings: list[FindingRecord] | None = None,
    evidence: list[EvidenceRecord] | None = None,
    audit_verification: AuditVerificationResult | None = None,
    report_id: str | None = None,
    created_at_utc: str | None = None,
    customer_name: str | None = None,
    environment: str = "development",
    scope_summary: str = "",
    authorization_summary: str = "",
    executive_summary: str = "",
    methodology_summary: str = "",
    limitations: list[str] | tuple[str, ...] | None = None,
    generated_by: str = "Aegis EV",
    tags: list[str] | tuple[str, ...] | None = None,
) -> ReportRecord:
    if evidence_store is not None:
        store_findings = evidence_store.list_findings()
        store_evidence = evidence_store.list_evidence()
        findings = store_findings if findings is None else findings
        evidence = store_evidence if evidence is None else evidence
    finding_sections = [FindingReportSection.from_finding(item) for item in (findings or [])]
    evidence_sections = [EvidenceReportSection.from_evidence(item) for item in (evidence or [])]
    return ReportRecord(
        report_id=report_id or f"report_{uuid4().hex}",
        created_at_utc=created_at_utc or datetime.now(timezone.utc).isoformat(),
        project_name=project_name,
        customer_name=customer_name,
        environment=environment,
        scope_summary=scope_summary,
        authorization_summary=authorization_summary,
        executive_summary=executive_summary,
        methodology_summary=methodology_summary,
        findings=tuple(finding_sections),
        evidence_summary=tuple(evidence_sections),
        audit_summary=AuditSummary.from_verification(audit_verification),
        risk_summary=RiskSummary.from_findings(finding_sections),
        limitations=tuple(limitations or ()),
        generated_by=generated_by,
        tags=tuple(tags or ()),
    )


def render_report_json(report: ReportRecord) -> str:
    return canonical_json(report.to_dict())


def render_report_markdown(report: ReportRecord) -> str:
    data = report.to_dict()
    lines = [
        f"# {_md(data['project_name'])} Security Validation Report",
        "",
        "## Metadata",
        "",
        f"- Report ID: `{_md(data['report_id'])}`",
        f"- Created UTC: `{_md(data['created_at_utc'])}`",
        f"- Customer: {_md(data['customer_name'] or 'Not provided')}",
        f"- Environment: `{_md(data['environment'])}`",
        f"- Generated by: {_md(data['generated_by'])}",
        f"- Schema version: `{_md(data['schema_version'])}`",
        f"- Tags: {_md(', '.join(data['tags']) if data['tags'] else 'None')}",
        "",
        "## Scope",
        "",
        _paragraph(data["scope_summary"] or "No scope summary was provided."),
        "",
        "## Authorization",
        "",
        _paragraph(data["authorization_summary"] or "No authorization summary was provided."),
        "",
        "## Methodology",
        "",
        _paragraph(data["methodology_summary"] or "No methodology summary was provided."),
        "",
        "## Executive Summary",
        "",
        _paragraph(data["executive_summary"] or "No executive summary was provided."),
        "",
        "## Risk Summary",
        "",
        _risk_markdown(report.risk_summary),
        "",
        "## Findings Table",
        "",
        _findings_table(report.findings),
        "",
        "## Finding Details",
        "",
        _finding_details(report.findings),
        "",
        "## Evidence Summary",
        "",
        _evidence_table(report.evidence_summary),
        "",
        "## Audit Summary",
        "",
        _audit_markdown(report.audit_summary),
        "",
        "## Limitations",
        "",
        _limitations_markdown(data["limitations"]),
        "",
        "## Retest Status",
        "",
        _retest_markdown(report.findings),
        "",
        "## Footer",
        "",
        "This report is evidence-backed and deterministic. Tamper-evident audit logging is not tamper-proof storage. Findings are not confirmed unless their recorded status or verification state says so.",
        "",
    ]
    return "\n".join(lines)


def _count_by(findings: list[FindingReportSection], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        value = getattr(finding, field_name)
        key = str(value or "none")
        counts[key] = counts.get(key, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def _md(value: Any) -> str:
    text = str(_enum_text(value))
    replacements = {
        "\\": "\\\\",
        "|": "\\|",
        "`": "\\`",
        "*": "\\*",
        "_": "\\_",
        "[": "\\[",
        "]": "\\]",
        "<": "&lt;",
        ">": "&gt;",
    }
    text = text.replace("\r", " ").replace("\n", " ")
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _paragraph(value: Any) -> str:
    return _md(value)


def _risk_markdown(summary: RiskSummary) -> str:
    sections = [
        ("Total findings", {"total": summary.total_findings}),
        ("By severity", summary.by_severity),
        ("By status", summary.by_status),
        ("By verification state", summary.by_verification_state),
        ("By target", summary.by_target),
        ("By category", summary.by_category),
    ]
    lines: list[str] = []
    for title, values in sections:
        lines.append(f"- {_md(title)}: {_md(_inline_counts(values))}")
    return "\n".join(lines)


def _findings_table(findings: tuple[FindingReportSection, ...]) -> str:
    if not findings:
        return "No findings were recorded."
    lines = [
        "| ID | Title | Severity | Confidence | Status | Verification | Target | Evidence |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(finding.finding_id),
                    _md(finding.title),
                    _md(finding.severity),
                    _md(finding.confidence),
                    _md(finding.status),
                    _md(finding.verification_state),
                    _md(finding.normalized_target or finding.target or "Not provided"),
                    _md(", ".join(finding.evidence_ids) if finding.evidence_ids else "None"),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _finding_details(findings: tuple[FindingReportSection, ...]) -> str:
    if not findings:
        return "No finding details are available."
    blocks: list[str] = []
    for finding in findings:
        status_note = "Recorded as confirmed." if finding.status == "confirmed" or finding.verification_state == "verified" else "Not recorded as confirmed."
        blocks.extend(
            [
                f"### {_md(finding.finding_id)} - {_md(finding.title)}",
                "",
                f"- Severity: `{_md(finding.severity)}`",
                f"- Confidence: `{_md(finding.confidence)}`",
                f"- Status: `{_md(finding.status)}`",
                f"- Verification state: `{_md(finding.verification_state)}`",
                f"- Confirmation note: {_md(status_note)}",
                f"- Target: {_md(finding.target or 'Not provided')}",
                f"- Normalized target: {_md(finding.normalized_target or 'Not provided')}",
                f"- Category: {_md(finding.category)}",
                f"- CWE: {_md(finding.cwe_id or 'Not provided')}",
                f"- OWASP reference: {_md(finding.owasp_reference or 'Not provided')}",
                f"- CVSS score: {_md(finding.cvss_score if finding.cvss_score is not None else 'Not provided')}",
                f"- Evidence IDs: {_md(', '.join(finding.evidence_ids) if finding.evidence_ids else 'None')}",
                f"- Remediation: {_md(finding.remediation or 'Not provided')}",
                f"- Retest status: `{_md(finding.retest_status)}`",
                f"- Tags: {_md(', '.join(finding.tags) if finding.tags else 'None')}",
                "",
            ]
        )
    return "\n".join(blocks).rstrip()


def _evidence_table(evidence: tuple[EvidenceReportSection, ...]) -> str:
    if not evidence:
        return "No evidence references were recorded."
    lines = [
        "| ID | Type | Source | Target | Title | Summary | Audit Event | Adapter | Confidence | Redacted | Tags |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in evidence:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(item.evidence_id),
                    _md(item.evidence_type),
                    _md(item.source_type),
                    _md(item.normalized_target or item.target or "Not provided"),
                    _md(item.title),
                    _md(item.summary),
                    _md(item.related_audit_event_id or "None"),
                    _md(item.related_adapter_id or "None"),
                    _md(item.confidence),
                    _md(item.redaction_applied),
                    _md(", ".join(item.tags) if item.tags else "None"),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _audit_markdown(summary: AuditSummary) -> str:
    lines = [
        f"- Total audit events: {_md(summary.total_events if summary.total_events is not None else 'Not provided')}",
        f"- Verification valid: {_md(summary.verification_valid if summary.verification_valid is not None else 'Not provided')}",
        f"- Hash chain status: `{_md(summary.hash_chain_status)}`",
        f"- Latest event hash: `{_md(summary.latest_event_hash or 'Not provided')}`",
        f"- Warning: {_md(summary.warning)}",
    ]
    if summary.errors:
        lines.append(f"- Errors: {_md('; '.join(summary.errors))}")
    return "\n".join(lines)


def _limitations_markdown(limitations: list[str]) -> str:
    if not limitations:
        return "- No limitations were provided."
    return "\n".join(f"- {_md(item)}" for item in limitations)


def _retest_markdown(findings: tuple[FindingReportSection, ...]) -> str:
    if not findings:
        return "No retest status is available."
    counts = _count_by(list(findings), "retest_status")
    return "\n".join(f"- {_md(key)}: {count}" for key, count in counts.items())


def _inline_counts(values: dict[str, int]) -> str:
    if not values:
        return "none"
    return ", ".join(f"{key}={values[key]}" for key in sorted(values))


def _enum_text(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def _safe_text(value: Any) -> Any:
    if value is None:
        return None
    redacted = redact_value(value)
    if isinstance(redacted, str):
        redacted = INLINE_BEARER_RE.sub("Bearer <redacted>", redacted)
        redacted = INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
    return redacted
