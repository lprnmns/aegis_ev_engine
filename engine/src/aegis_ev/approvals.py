from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit import AuditEvent, AuditLog, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence
from .models import ImpactLevel, PolicyDecision, PolicyDecisionType, ToolIntent


class ApprovalActorType(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    LLM = "llm"
    SYSTEM = "system"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    CONSUMED = "consumed"


def _utc_now(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat()


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str = field(default_factory=lambda: f"approval_{uuid4().hex}")
    created_at_utc: str = field(default_factory=_utc_now)
    updated_at_utc: str | None = None
    requested_by: str = ""
    requested_actor_type: ApprovalActorType | str = ApprovalActorType.HUMAN
    action_type: str = ""
    target: str | None = None
    normalized_target: str | None = None
    impact_level: ImpactLevel | str = ImpactLevel.GREEN
    reason: str = ""
    policy_decision_code: str = ""
    adapter_id: str | None = None
    adapter_action: str | None = None
    sanitized_arguments: dict[str, Any] = field(default_factory=dict)
    required_approval_scope: dict[str, Any] = field(default_factory=dict)
    status: ApprovalStatus | str = ApprovalStatus.PENDING
    expires_at_utc: str | None = None
    approved_by: str | None = None
    approved_at_utc: str | None = None
    rejected_by: str | None = None
    rejected_at_utc: str | None = None
    decision_reason: str | None = None
    related_audit_event_id: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        requested_actor_type = _enum_value(ApprovalActorType, self.requested_actor_type, "requested_actor_type")
        status = _enum_value(ApprovalStatus, self.status, "status")
        impact_level = _enum_value(ImpactLevel, self.impact_level, "impact_level")
        if not self.requested_by.strip():
            raise ValueError("requested_by is required")
        if not self.action_type.strip():
            raise ValueError("action_type is required")
        object.__setattr__(self, "requested_actor_type", requested_actor_type)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "impact_level", impact_level)
        object.__setattr__(self, "updated_at_utc", self.updated_at_utc or self.created_at_utc)
        object.__setattr__(self, "target", redact_target(self.target))
        object.__setattr__(self, "normalized_target", redact_target(self.normalized_target))
        object.__setattr__(self, "sanitized_arguments", redact_value(self.sanitized_arguments))
        object.__setattr__(self, "required_approval_scope", redact_value(self.required_approval_scope))
        object.__setattr__(self, "metadata", redact_value(self.metadata))
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at_utc is None:
            return False
        expires = _datetime(self.expires_at_utc)
        now = now or datetime.now(timezone.utc)
        return now > expires


class ApprovalStore:
    def __init__(self) -> None:
        self._items: dict[str, ApprovalRequest] = {}

    def add(self, approval: ApprovalRequest) -> ApprovalRequest:
        if approval.approval_id in self._items:
            raise ValueError(f"Duplicate approval_id: {approval.approval_id}")
        self._items[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str, *, now: datetime | None = None) -> ApprovalRequest:
        try:
            approval = self._items[approval_id]
        except KeyError as exc:
            raise KeyError(f"Unknown approval_id: {approval_id}") from exc
        approval = self._refresh_expiration(approval, now=now)
        self._items[approval_id] = approval
        return approval

    def list_approvals(self, *, now: datetime | None = None) -> list[ApprovalRequest]:
        return [self.get(key, now=now) for key in sorted(self._items)]

    def list_pending(self, *, now: datetime | None = None) -> list[ApprovalRequest]:
        return [item for item in self.list_approvals(now=now) if item.status == ApprovalStatus.PENDING.value]

    def approve(
        self,
        approval_id: str,
        *,
        approved_by: str,
        actor_type: ApprovalActorType | str,
        decision_reason: str = "",
        now: datetime | None = None,
    ) -> ApprovalRequest:
        approval = self.get(approval_id, now=now)
        actor = _enum_value(ApprovalActorType, actor_type, "actor_type")
        if actor != ApprovalActorType.HUMAN.value:
            raise ValueError("Only human actors may approve requests")
        if approval.requested_by == approved_by and approval.requested_actor_type in {
            ApprovalActorType.AGENT.value,
            ApprovalActorType.LLM.value,
        }:
            raise ValueError("Agents and LLMs cannot approve their own requests")
        self._ensure_pending(approval)
        updated = _replace_approval(
            approval,
            status=ApprovalStatus.APPROVED.value,
            approved_by=approved_by,
            approved_at_utc=_utc_now(now),
            decision_reason=decision_reason or "Approved by human reviewer",
            updated_at_utc=_utc_now(now),
        )
        self._items[approval_id] = updated
        return updated

    def reject(
        self,
        approval_id: str,
        *,
        rejected_by: str,
        actor_type: ApprovalActorType | str,
        decision_reason: str = "",
        now: datetime | None = None,
    ) -> ApprovalRequest:
        approval = self.get(approval_id, now=now)
        actor = _enum_value(ApprovalActorType, actor_type, "actor_type")
        if actor != ApprovalActorType.HUMAN.value:
            raise ValueError("Only human actors may reject requests")
        self._ensure_pending(approval)
        updated = _replace_approval(
            approval,
            status=ApprovalStatus.REJECTED.value,
            rejected_by=rejected_by,
            rejected_at_utc=_utc_now(now),
            decision_reason=decision_reason or "Rejected by human reviewer",
            updated_at_utc=_utc_now(now),
        )
        self._items[approval_id] = updated
        return updated

    def expire(self, approval_id: str, *, now: datetime | None = None) -> ApprovalRequest:
        approval = self.get(approval_id, now=now)
        if approval.status not in {ApprovalStatus.PENDING.value, ApprovalStatus.APPROVED.value}:
            raise ValueError("Only pending or approved approvals may expire")
        updated = _replace_approval(
            approval,
            status=ApprovalStatus.EXPIRED.value,
            updated_at_utc=_utc_now(now),
        )
        self._items[approval_id] = updated
        return updated

    def cancel(self, approval_id: str, *, cancelled_by: str, now: datetime | None = None) -> ApprovalRequest:
        approval = self.get(approval_id, now=now)
        self._ensure_pending(approval)
        updated = _replace_approval(
            approval,
            status=ApprovalStatus.CANCELLED.value,
            decision_reason=f"Cancelled by {cancelled_by}",
            updated_at_utc=_utc_now(now),
        )
        self._items[approval_id] = updated
        return updated

    def consume(self, approval_id: str, *, consumer: str, now: datetime | None = None) -> ApprovalRequest:
        approval = self.get(approval_id, now=now)
        if approval.status != ApprovalStatus.APPROVED.value:
            raise ValueError("Only approved approvals may be consumed")
        if approval.is_expired(now):
            updated = self.expire(approval_id, now=now)
            raise ValueError(f"Approval is expired: {updated.approval_id}")
        updated = _replace_approval(
            approval,
            status=ApprovalStatus.CONSUMED.value,
            decision_reason=f"Consumed by {consumer}",
            updated_at_utc=_utc_now(now),
        )
        self._items[approval_id] = updated
        return updated

    def find_matching(
        self,
        *,
        target: str,
        normalized_target: str | None,
        action_type: str,
        impact_level: ImpactLevel | str,
        adapter_id: str | None = None,
        adapter_action: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRequest | None:
        for approval in self.list_approvals(now=now):
            if approval.status != ApprovalStatus.APPROVED.value:
                continue
            if approval.is_expired(now):
                continue
            if approval.target != redact_target(target):
                continue
            if approval.normalized_target != redact_target(normalized_target):
                continue
            if approval.action_type != action_type:
                continue
            if approval.impact_level != _enum_value(ImpactLevel, impact_level, "impact_level"):
                continue
            if approval.adapter_id != adapter_id:
                continue
            if approval.adapter_action != adapter_action:
                continue
            scope = approval.required_approval_scope
            if scope.get("target") not in {None, redact_target(target)}:
                continue
            if scope.get("action_type") not in {None, action_type}:
                continue
            if scope.get("impact_level") not in {None, _enum_value(ImpactLevel, impact_level, "impact_level")}:
                continue
            if scope.get("adapter_id") not in {None, adapter_id}:
                continue
            if scope.get("adapter_action") not in {None, adapter_action}:
                continue
            return approval
        return None

    def export_json(self, path: str | Path) -> None:
        payload = {"approvals": [record.to_dict() for record in self.list_approvals()]}
        Path(path).write_text(canonical_json(payload) + "\n", encoding="utf-8")

    @classmethod
    def import_json(cls, path: str | Path) -> ApprovalStore:
        store = cls()
        file_path = Path(path)
        if not file_path.exists():
            return store
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed approval store JSON: {exc.msg}") from exc
        for item in payload.get("approvals", []):
            store.add(ApprovalRequest(**item))
        return store

    def export_jsonl(self, path: str | Path) -> None:
        lines = [canonical_json({"record_type": "approval", "record": item.to_dict()}) for item in self.list_approvals()]
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    @classmethod
    def import_jsonl(cls, path: str | Path) -> ApprovalStore:
        store = cls()
        file_path = Path(path)
        if not file_path.exists():
            return store
        for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                raise ValueError(f"line {line_number}: empty approval store record")
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: malformed JSON: {exc.msg}") from exc
            if payload.get("record_type") != "approval":
                raise ValueError(f"line {line_number}: unknown record_type")
            store.add(ApprovalRequest(**payload.get("record", {})))
        return store

    def _refresh_expiration(self, approval: ApprovalRequest, *, now: datetime | None = None) -> ApprovalRequest:
        if approval.status in {ApprovalStatus.PENDING.value, ApprovalStatus.APPROVED.value} and approval.is_expired(now):
            return _replace_approval(approval, status=ApprovalStatus.EXPIRED.value, updated_at_utc=_utc_now(now))
        return approval

    @staticmethod
    def _ensure_pending(approval: ApprovalRequest) -> None:
        if approval.status != ApprovalStatus.PENDING.value:
            raise ValueError(f"Approval request is not pending: {approval.status}")


def approval_from_policy_decision(
    decision: PolicyDecision,
    *,
    requested_by: str,
    requested_actor_type: ApprovalActorType | str,
    adapter_id: str | None = None,
    adapter_action: str | None = None,
    sanitized_arguments: dict[str, Any] | None = None,
    required_approval_scope: dict[str, Any] | None = None,
    expires_at_utc: str | None = None,
    related_audit_event_id: str | None = None,
    tags: tuple[str, ...] = (),
    metadata: dict[str, Any] | None = None,
) -> ApprovalRequest:
    if decision.decision != PolicyDecisionType.REQUIRES_APPROVAL:
        raise ValueError("Policy decision does not require approval")
    details = decision.to_audit_details()
    return ApprovalRequest(
        requested_by=requested_by,
        requested_actor_type=requested_actor_type,
        action_type=details["action_type"],
        target=details["target"],
        normalized_target=details["normalized_target"],
        impact_level=details["impact_level"],
        reason=details["message"],
        policy_decision_code=decision.code,
        adapter_id=adapter_id or details.get("adapter"),
        adapter_action=adapter_action,
        sanitized_arguments=sanitized_arguments or {},
        required_approval_scope=required_approval_scope
        or {
            "target": details["target"],
            "normalized_target": details["normalized_target"],
            "action_type": details["action_type"],
            "impact_level": details["impact_level"],
            "adapter_id": adapter_id or details.get("adapter"),
            "adapter_action": adapter_action,
        },
        expires_at_utc=expires_at_utc,
        related_audit_event_id=related_audit_event_id,
        tags=tags,
        metadata=metadata or {},
    )


def approval_allows_request(
    approval: ApprovalRequest,
    *,
    target: str,
    normalized_target: str | None,
    action_type: str,
    impact_level: ImpactLevel | str,
    adapter_id: str | None = None,
    adapter_action: str | None = None,
    now: datetime | None = None,
) -> bool:
    if approval.status != ApprovalStatus.APPROVED.value or approval.is_expired(now):
        return False
    if approval.target != redact_target(target):
        return False
    if approval.normalized_target != redact_target(normalized_target):
        return False
    if approval.action_type != action_type:
        return False
    if approval.impact_level != _enum_value(ImpactLevel, impact_level, "impact_level"):
        return False
    if approval.adapter_id != adapter_id:
        return False
    if approval.adapter_action != adapter_action:
        return False
    scope = approval.required_approval_scope
    return (
        scope.get("target") in {None, redact_target(target)}
        and scope.get("normalized_target") in {None, redact_target(normalized_target)}
        and scope.get("action_type") in {None, action_type}
        and scope.get("impact_level") in {None, _enum_value(ImpactLevel, impact_level, "impact_level")}
        and scope.get("adapter_id") in {None, adapter_id}
        and scope.get("adapter_action") in {None, adapter_action}
    )


def apply_approval_to_intent(
    intent: ToolIntent,
    approval: ApprovalRequest | None,
    *,
    normalized_target: str | None = None,
    adapter_action: str | None = None,
    now: datetime | None = None,
) -> ToolIntent:
    if approval is None:
        return intent
    if not approval_allows_request(
        approval,
        target=intent.target,
        normalized_target=normalized_target,
        action_type=intent.action_type,
        impact_level=intent.impact,
        adapter_id=intent.adapter,
        adapter_action=adapter_action,
        now=now,
    ):
        return intent
    return ToolIntent(
        adapter=intent.adapter,
        target=intent.target,
        impact=intent.impact,
        budget=intent.budget,
        reason=intent.reason,
        action_type=intent.action_type,
        requires_authentication=intent.requires_authentication,
        requests_used=intent.requests_used,
        approval_id=approval.approval_id,
        approval_granted=True,
    )


def append_approval_audit_event(
    audit_log: AuditLog,
    approval: ApprovalRequest,
    *,
    event_type: str,
    actor: str,
    decision_reason: str | None = None,
) -> AuditEvent:
    return audit_log.append(
        actor=actor,
        action=event_type,
        target=approval.target,
        details={
            "approval_id": approval.approval_id,
            "action_type": approval.action_type,
            "status": approval.status,
            "requested_by": approval.requested_by,
            "requested_actor_type": approval.requested_actor_type,
            "adapter_id": approval.adapter_id,
            "adapter_action": approval.adapter_action,
            "required_approval_scope": approval.required_approval_scope,
            "decision_reason": decision_reason or approval.decision_reason,
        },
        event_type=event_type,
        normalized_target=approval.normalized_target,
        impact_level=approval.impact_level,
        decision_code=approval.policy_decision_code,
        allowed=approval.status in {ApprovalStatus.APPROVED.value, ApprovalStatus.CONSUMED.value},
        required_approval=True,
    )


def evidence_from_approval_request(
    approval: ApprovalRequest,
    *,
    source_id: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.APPROVAL_EVENT,
        source_type=EvidenceSourceType.HUMAN if approval.requested_actor_type == ApprovalActorType.HUMAN.value else EvidenceSourceType.UNKNOWN,
        source_id=source_id or approval.approval_id,
        target=approval.target,
        normalized_target=approval.normalized_target,
        title=f"Approval {approval.status}: {approval.action_type}",
        summary=approval.reason,
        structured_data=approval.to_dict(),
        related_audit_event_id=approval.related_audit_event_id,
        related_adapter_id=approval.adapter_id,
        tags=approval.tags,
        confidence=FindingConfidence.HIGH,
        redaction_applied=True,
    )


def _replace_approval(approval: ApprovalRequest, **updates: Any) -> ApprovalRequest:
    payload = approval.to_dict()
    payload.update(updates)
    return ApprovalRequest(**payload)


def _enum_value(enum_type: type[Enum], value: Enum | str, field_name: str) -> str:
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value}") from exc

def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
