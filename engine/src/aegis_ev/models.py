from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Any


class ImpactLevel(str, Enum):
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


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
        if self.max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be > 0")


@dataclass(frozen=True)
class PolicyBudget:
    max_requests: int
    max_requests_per_minute: int = 30
    max_concurrency: int = 2

    def validate(self) -> None:
        if self.max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if self.max_requests_per_minute <= 0:
            raise ValueError("max_requests_per_minute must be > 0")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be > 0")


@dataclass(frozen=True)
class AuthorizationProfile:
    owner: str
    allowed_domains: list[str]
    allowed_cidrs: list[str] = field(default_factory=list)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    environment: Environment | str | None = None
    allowed_impact_levels: list[ImpactLevel | str] = field(default_factory=list)
    request_budget: PolicyBudget | None = None
    max_requests_per_minute: int = 30
    max_concurrency: int = 2
    approved_egress_profiles: list[str] = field(default_factory=list)
    require_approval_for_authenticated_checks: bool = True
    require_approval_for_amber: bool = True
    require_approval_for_production_amber: bool = True
    expires_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        expiry = self.valid_until or self.expires_at
        if expiry is None:
            return False
        now = now or datetime.now(timezone.utc)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now > expiry

    def not_yet_valid(self, now: datetime | None = None) -> bool:
        if self.valid_from is None:
            return False
        now = now or datetime.now(timezone.utc)
        start = self.valid_from
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        return now < start

    def validation_errors(self, now: datetime | None = None) -> list[str]:
        errors: list[str] = []
        if not self.owner.strip():
            errors.append("owner/customer identifier is required")
        if not self.allowed_domains and not self.allowed_cidrs:
            errors.append("scope allowlist must not be empty")
        for domain in self.allowed_domains:
            if not domain.strip() or "://" in domain or "/" in domain:
                errors.append(f"invalid allowed domain: {domain}")
        for cidr in self.allowed_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                errors.append(f"invalid allowed CIDR: {cidr}")
        if self.valid_from is None:
            errors.append("valid_from is required")
        if self.valid_until is None:
            errors.append("valid_until is required")
        if self.valid_from and self.valid_until:
            start = _ensure_aware(self.valid_from)
            end = _ensure_aware(self.valid_until)
            if start >= end:
                errors.append("valid_from must be before valid_until")
        if self.valid_from and self.not_yet_valid(now):
            errors.append("authorization profile is not yet valid")
        if self.is_expired(now):
            errors.append("authorization profile is expired")
        try:
            Environment(self.environment)  # type: ignore[arg-type]
        except ValueError:
            errors.append("environment must be development, staging, or production")
        if not self.allowed_impact_levels:
            errors.append("allowed impact levels must not be empty")
        else:
            for level in self.allowed_impact_levels:
                try:
                    ImpactLevel(level)
                except ValueError:
                    errors.append(f"unknown allowed impact level: {level}")
        budget = self.effective_budget()
        try:
            budget.validate()
        except ValueError as exc:
            errors.append(f"invalid authorization budget: {exc}")
        return errors

    def effective_budget(self) -> PolicyBudget:
        return self.request_budget or PolicyBudget(
            max_requests=max(self.max_requests_per_minute, 1),
            max_requests_per_minute=self.max_requests_per_minute,
            max_concurrency=self.max_concurrency,
        )

    def normalized_environment(self) -> Environment:
        return Environment(self.environment)  # type: ignore[arg-type]

    def normalized_allowed_impacts(self) -> set[ImpactLevel]:
        return {ImpactLevel(level) for level in self.allowed_impact_levels}


@dataclass(frozen=True)
class ToolIntent:
    adapter: str
    target: str
    impact: ImpactLevel | str
    budget: RequestBudget = field(default_factory=RequestBudget)
    reason: str = ""
    action_type: str = "run_adapter"
    requires_authentication: bool = False
    requests_used: int = 0
    approval_id: str | None = None
    approval_granted: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str
    intent: ToolIntent
    code: str = "policy_decision"
    message: str = ""
    required_approval: bool = False
    normalized_target: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecisionType.ALLOW

    def to_audit_details(self) -> dict[str, Any]:
        return {
            "target": _redact_target(self.intent.target),
            "normalized_target": self.normalized_target,
            "action_type": self.intent.action_type,
            "adapter": self.intent.adapter,
            "impact_level": _enum_value(self.intent.impact),
            "decision": self.decision.value,
            "decision_code": self.code,
            "message": self.message or self.reason,
            "required_approval": self.required_approval,
            "approval_id": self.intent.approval_id if self.intent.approval_granted else None,
        }

    def to_public_dict(self) -> dict[str, Any]:
        return self.to_audit_details() | {
            "allowed": self.allowed,
            "reason": self.reason,
        }


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


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _enum_value(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _redact_target(target: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    try:
        parsed = urlsplit(target)
    except ValueError:
        return "<invalid-target>"
    host = parsed.hostname or ""
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
