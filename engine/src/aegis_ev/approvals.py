from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from .models import ToolIntent


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ApprovalRequest:
    id: str
    intent: ToolIntent
    reason: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decided_at: datetime | None = None
    comment: str = ""


class ApprovalQueue:
    def __init__(self) -> None:
        self._items: dict[str, ApprovalRequest] = {}

    def create(self, intent: ToolIntent, reason: str) -> ApprovalRequest:
        request = ApprovalRequest(id=f"approval_{uuid4().hex}", intent=intent, reason=reason)
        self._items[request.id] = request
        return request

    def decide(self, approval_id: str, approved: bool, comment: str = "") -> ApprovalRequest:
        if approval_id not in self._items:
            raise KeyError(f"Unknown approval id: {approval_id}")
        item = self._items[approval_id]
        if item.status != ApprovalStatus.PENDING:
            raise ValueError("Approval request is already decided")
        item.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        item.decided_at = datetime.now(timezone.utc)
        item.comment = comment
        return item

    def pending(self) -> list[ApprovalRequest]:
        return [item for item in self._items.values() if item.status == ApprovalStatus.PENDING]
