from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ImpactLevel(str, Enum):
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class PolicyDecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


class EvidenceKind(str, Enum):
    HTTP_HEADER_OBSERVATION = "http_header_observation"
    POLICY_DECISION = "policy_decision"


@dataclass(frozen=True)
class RequestBudget:
    max_requests: int = 3
    timeout_seconds: int = 10
    max_response_bytes: int = 1_000_000

    def validate(self) -> None:
        if self.max_requests < 0:
            raise ValueError("max_requests must be >= 0")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be > 0")


@dataclass(frozen=True)
class AuthorizationProfile:
    owner: str
    allowed_domains: list[str]
    allowed_cidrs: list[str] = field(default_factory=list)
    expires_at: datetime | None = None
    max_requests_per_minute: int = 30
    max_concurrency: int = 2
    approved_egress_profiles: list[str] = field(default_factory=list)

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now > expiry


@dataclass(frozen=True)
class ToolIntent:
    adapter: str
    target: str
    impact: ImpactLevel
    budget: RequestBudget = field(default_factory=RequestBudget)
    reason: str = ""
    requires_authentication: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str
    intent: ToolIntent

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecisionType.ALLOW


@dataclass(frozen=True)
class Evidence:
    id: str
    kind: EvidenceKind
    target: str
    observed_at: datetime
    data: dict[str, Any]


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    evidence_ids: list[str]
    remediation: str
    status: str = "candidate"
