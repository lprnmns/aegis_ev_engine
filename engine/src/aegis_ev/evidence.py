from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit import AuditEvent, canonical_json, redact_target, redact_value
from .models import PolicyDecision


class EvidenceType(str, Enum):
    POLICY_DECISION = "policy_decision"
    ADAPTER_PLAN = "adapter_plan"
    ADAPTER_OUTPUT = "adapter_output"
    AUDIT_EVENT = "audit_event"
    APPROVAL_EVENT = "approval_event"
    MANUAL_NOTE = "manual_note"
    SCREENSHOT_REFERENCE = "screenshot_reference"
    REQUEST_RESPONSE_REFERENCE = "request_response_reference"
    UNKNOWN = "unknown"


class EvidenceSourceType(str, Enum):
    POLICY = "policy"
    ADAPTER = "adapter"
    WEB_HEADER_CHECK = "web_header_check"
    API_IMPORT = "api_import"
    SAFE_HTTP_FETCH = "safe_http_fetch"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    AUDIT = "audit"
    HUMAN = "human"
    AI_VERIFIER = "ai_verifier"
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    DRAFT = "draft"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    RETEST_REQUIRED = "retest_required"


class RetestStatus(str, Enum):
    NOT_RETESTED = "not_retested"
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class VerificationState(str, Enum):
    UNVERIFIED = "unverified"
    EVIDENCE_BACKED = "evidence_backed"
    HUMAN_REVIEW_REQUIRED = "human_review_required"
    VERIFIED = "verified"
    REJECTED = "rejected"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str = field(default_factory=lambda: f"evidence_{uuid4().hex}")
    created_at_utc: str = field(default_factory=_utc_now)
    evidence_type: EvidenceType | str = EvidenceType.UNKNOWN
    source_type: EvidenceSourceType | str = EvidenceSourceType.UNKNOWN
    source_id: str | None = None
    target: str | None = None
    normalized_target: str | None = None
    title: str = ""
    summary: str = ""
    redacted_raw: Any | None = None
    structured_data: dict[str, Any] = field(default_factory=dict)
    hash: str = ""
    related_audit_event_id: str | None = None
    related_adapter_id: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    confidence: FindingConfidence | str = FindingConfidence.LOW
    redaction_applied: bool = False

    def __post_init__(self) -> None:
        evidence_type = _enum_value(EvidenceType, self.evidence_type, "evidence_type")
        source_type = _enum_value(EvidenceSourceType, self.source_type, "source_type")
        confidence = _enum_value(FindingConfidence, self.confidence, "confidence")
        redacted_raw = redact_value(self.redacted_raw)
        structured_data = redact_value(self.structured_data)
        target = redact_target(self.target)
        normalized_target = redact_target(self.normalized_target)
        redaction_applied = (
            _stable_repr(redacted_raw) != _stable_repr(self.redacted_raw)
            or _stable_repr(structured_data) != _stable_repr(self.structured_data)
            or target != self.target
            or normalized_target != self.normalized_target
        )
        object.__setattr__(self, "evidence_type", evidence_type)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "redacted_raw", redacted_raw)
        object.__setattr__(self, "structured_data", structured_data)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "normalized_target", normalized_target)
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))
        object.__setattr__(self, "redaction_applied", bool(self.redaction_applied or redaction_applied))
        object.__setattr__(self, "hash", self.compute_hash())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def serialize(self) -> str:
        return canonical_json(self.to_dict())

    def compute_hash(self) -> str:
        payload = self.to_dict()
        payload.pop("hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str = field(default_factory=lambda: f"finding_{uuid4().hex}")
    created_at_utc: str = field(default_factory=_utc_now)
    updated_at_utc: str | None = None
    title: str = ""
    description: str = ""
    severity: FindingSeverity | str = FindingSeverity.LOW
    confidence: FindingConfidence | str = FindingConfidence.LOW
    status: FindingStatus | str = FindingStatus.CANDIDATE
    target: str | None = None
    normalized_target: str | None = None
    category: str = "uncategorized"
    cwe_id: str | None = None
    owasp_reference: str | None = None
    cvss_score: float | None = None
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    remediation: str = ""
    retest_status: RetestStatus | str = RetestStatus.NOT_RETESTED
    verification_state: VerificationState | str = VerificationState.UNVERIFIED
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        severity = _enum_value(FindingSeverity, self.severity, "severity")
        confidence = _enum_value(FindingConfidence, self.confidence, "confidence")
        status = _enum_value(FindingStatus, self.status, "status")
        retest_status = _enum_value(RetestStatus, self.retest_status, "retest_status")
        verification_state = _enum_value(VerificationState, self.verification_state, "verification_state")
        evidence_ids = tuple(sorted(set(self.evidence_ids)))
        if verification_state in {VerificationState.EVIDENCE_BACKED.value, VerificationState.VERIFIED.value} and not evidence_ids:
            raise ValueError("verified or evidence-backed findings require evidence")
        if status == FindingStatus.CONFIRMED.value and not evidence_ids:
            raise ValueError("confirmed findings require evidence")
        if self.cvss_score is not None and not 0.0 <= float(self.cvss_score) <= 10.0:
            raise ValueError("cvss_score must be between 0.0 and 10.0")
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "retest_status", retest_status)
        object.__setattr__(self, "verification_state", verification_state)
        object.__setattr__(self, "target", redact_target(self.target))
        object.__setattr__(self, "normalized_target", redact_target(self.normalized_target))
        object.__setattr__(self, "evidence_ids", evidence_ids)
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))
        if self.updated_at_utc is None:
            object.__setattr__(self, "updated_at_utc", self.created_at_utc)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))

    def serialize(self) -> str:
        return canonical_json(self.to_dict())


class EvidenceStore:
    """Small in-memory evidence/finding store with optional JSON/JSONL export."""

    def __init__(self) -> None:
        self._evidence: dict[str, EvidenceRecord] = {}
        self._findings: dict[str, FindingRecord] = {}

    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        if evidence.evidence_id in self._evidence:
            raise ValueError(f"Duplicate evidence_id: {evidence.evidence_id}")
        self._evidence[evidence.evidence_id] = evidence
        return evidence

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        try:
            return self._evidence[evidence_id]
        except KeyError as exc:
            raise KeyError(f"Unknown evidence_id: {evidence_id}") from exc

    def list_evidence(self) -> list[EvidenceRecord]:
        return [self._evidence[key] for key in sorted(self._evidence)]

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        if finding.finding_id in self._findings:
            raise ValueError(f"Duplicate finding_id: {finding.finding_id}")
        missing = [evidence_id for evidence_id in finding.evidence_ids if evidence_id not in self._evidence]
        if missing:
            raise KeyError(f"Unknown evidence_id(s): {', '.join(missing)}")
        self._findings[finding.finding_id] = finding
        return finding

    def get_finding(self, finding_id: str) -> FindingRecord:
        try:
            return self._findings[finding_id]
        except KeyError as exc:
            raise KeyError(f"Unknown finding_id: {finding_id}") from exc

    def list_findings(self) -> list[FindingRecord]:
        return [self._findings[key] for key in sorted(self._findings)]

    def link_evidence_to_finding(self, evidence_id: str, finding_id: str) -> FindingRecord:
        self.get_evidence(evidence_id)
        finding = self.get_finding(finding_id)
        evidence_ids = tuple(sorted(set(finding.evidence_ids + (evidence_id,))))
        updated = _replace_finding(finding, evidence_ids=evidence_ids, updated_at_utc=_utc_now())
        self._findings[finding_id] = updated
        return updated

    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus | str,
        *,
        verification_state: VerificationState | str | None = None,
    ) -> FindingRecord:
        finding = self.get_finding(finding_id)
        updates: dict[str, Any] = {"status": status, "updated_at_utc": _utc_now()}
        if verification_state is not None:
            updates["verification_state"] = verification_state
        updated = _replace_finding(finding, **updates)
        self._findings[finding_id] = updated
        return updated

    def export_json(self, path: str | Path) -> None:
        payload = {
            "evidence": [record.to_dict() for record in self.list_evidence()],
            "findings": [record.to_dict() for record in self.list_findings()],
        }
        Path(path).write_text(canonical_json(payload) + "\n", encoding="utf-8")

    @classmethod
    def import_json(cls, path: str | Path) -> EvidenceStore:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed evidence store JSON: {exc.msg}") from exc
        store = cls()
        for item in payload.get("evidence", []):
            store.add_evidence(EvidenceRecord(**item))
        for item in payload.get("findings", []):
            store.add_finding(FindingRecord(**item))
        return store

    def export_jsonl(self, path: str | Path) -> None:
        lines: list[str] = []
        for record in self.list_evidence():
            lines.append(canonical_json({"record_type": "evidence", "record": record.to_dict()}))
        for record in self.list_findings():
            lines.append(canonical_json({"record_type": "finding", "record": record.to_dict()}))
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    @classmethod
    def import_jsonl(cls, path: str | Path) -> EvidenceStore:
        store = cls()
        text = Path(path).read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                raise ValueError(f"line {line_number}: empty evidence store record")
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: malformed JSON: {exc.msg}") from exc
            record_type = payload.get("record_type")
            record = payload.get("record", {})
            if record_type == "evidence":
                store.add_evidence(EvidenceRecord(**record))
            elif record_type == "finding":
                store.add_finding(FindingRecord(**record))
            else:
                raise ValueError(f"line {line_number}: unknown record_type")
        return store


def evidence_from_policy_decision(
    decision: PolicyDecision,
    *,
    source_id: str | None = None,
    related_audit_event_id: str | None = None,
) -> EvidenceRecord:
    details = decision.to_audit_details()
    return EvidenceRecord(
        evidence_type=EvidenceType.POLICY_DECISION,
        source_type=EvidenceSourceType.POLICY,
        source_id=source_id or decision.code,
        target=details.get("target"),
        normalized_target=details.get("normalized_target"),
        title=f"Policy decision: {decision.code}",
        summary=details.get("message") or decision.reason,
        structured_data=details | {"allowed": decision.allowed},
        related_audit_event_id=related_audit_event_id,
        confidence=FindingConfidence.HIGH,
        redaction_applied=True,
    )


def evidence_from_audit_event(event: AuditEvent) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.AUDIT_EVENT,
        source_type=EvidenceSourceType.AUDIT,
        source_id=event.event_id,
        target=event.target,
        normalized_target=event.normalized_target,
        title=f"Audit event: {event.event_type}",
        summary=f"{event.action} decision_code={event.decision_code}",
        structured_data=asdict(event),
        related_audit_event_id=event.event_id,
        confidence=FindingConfidence.HIGH,
        redaction_applied=True,
    )


def evidence_from_adapter_plan(plan: Any, *, source_id: str | None = None) -> EvidenceRecord:
    structured = {
        "allowed": getattr(plan, "allowed", None),
        "adapter_id": getattr(plan, "adapter_id", None),
        "action": getattr(plan, "action", None),
        "normalized_target": getattr(plan, "normalized_target", None),
        "sanitized_arguments": getattr(plan, "sanitized_arguments", {}),
        "impact_level": getattr(plan, "impact_level", None),
        "required_approval": getattr(plan, "required_approval", None),
        "estimated_budget": getattr(plan, "estimated_budget", {}),
        "audit_event_id": getattr(plan, "audit_event_id", None),
        "command_preview": getattr(plan, "command_preview", []),
        "execution_preview": getattr(plan, "execution_preview", None),
        "denial_reason": getattr(plan, "denial_reason", None),
        "decision_code": getattr(plan, "decision_code", None),
        "dry_run": getattr(plan, "dry_run", None),
    }
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_PLAN,
        source_type=EvidenceSourceType.ADAPTER,
        source_id=source_id or structured["adapter_id"],
        target=None,
        normalized_target=structured["normalized_target"],
        title=f"Adapter plan: {structured['adapter_id']}.{structured['action']}",
        summary="Allowed adapter plan" if structured["allowed"] else "Denied adapter plan",
        structured_data=structured,
        related_audit_event_id=structured["audit_event_id"],
        related_adapter_id=structured["adapter_id"],
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def candidate_finding_from_evidence(
    evidence: EvidenceRecord | list[EvidenceRecord],
    *,
    title: str,
    description: str,
    severity: FindingSeverity | str = FindingSeverity.LOW,
    confidence: FindingConfidence | str = FindingConfidence.LOW,
    remediation: str = "",
    category: str = "uncategorized",
    verification_state: VerificationState | str | None = None,
) -> FindingRecord:
    records = evidence if isinstance(evidence, list) else [evidence]
    if not records:
        return FindingRecord(
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            status=FindingStatus.DRAFT,
            remediation=remediation,
            category=category,
        )
    normalized_confidence = _enum_value(FindingConfidence, confidence, "confidence")
    state = verification_state or VerificationState.EVIDENCE_BACKED
    status = FindingStatus.CANDIDATE
    if normalized_confidence == FindingConfidence.LOW.value:
        status = FindingStatus.DRAFT
        state = VerificationState.HUMAN_REVIEW_REQUIRED
    return FindingRecord(
        title=title,
        description=description,
        severity=severity,
        confidence=normalized_confidence,
        status=status,
        target=records[0].target,
        normalized_target=records[0].normalized_target,
        category=category,
        evidence_ids=tuple(record.evidence_id for record in records),
        remediation=remediation,
        verification_state=state,
    )


def _replace_finding(finding: FindingRecord, **updates: Any) -> FindingRecord:
    payload = finding.to_dict()
    payload.update(updates)
    return FindingRecord(**payload)


def _enum_value(enum_type: type[Enum], value: Enum | str, field_name: str) -> str:
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value}") from exc


def _stable_repr(value: Any) -> str:
    try:
        return canonical_json(value)
    except TypeError:
        return repr(value)
