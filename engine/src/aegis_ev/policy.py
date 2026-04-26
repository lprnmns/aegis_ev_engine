from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .models import (
    AuthorizationProfile,
    ImpactLevel,
    PolicyDecision,
    PolicyDecisionType,
    ToolIntent,
)


@dataclass(frozen=True)
class PolicyConfig:
    safe_mode: bool = True
    stop_on_block: bool = True
    require_approval_for_authenticated_checks: bool = True
    allowed_schemes: tuple[str, ...] = ("http", "https")


class PolicyEngine:
    """Deterministic enforcement point before any target interaction."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def evaluate(self, intent: ToolIntent, auth: AuthorizationProfile) -> PolicyDecision:
        try:
            intent.budget.validate()
        except ValueError as exc:
            return self._deny(intent, f"Invalid request budget: {exc}")

        if auth.is_expired():
            return self._deny(intent, "Authorization profile is expired")

        parsed = urlparse(intent.target)
        if parsed.scheme not in self.config.allowed_schemes:
            return self._deny(intent, f"Unsupported URL scheme: {parsed.scheme or '<empty>'}")

        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return self._deny(intent, "Target host is missing")

        if not self._host_allowed(host, auth.allowed_domains):
            return self._deny(intent, f"Target host '{host}' is outside allowed domains")

        if intent.impact == ImpactLevel.RED:
            return self._approval(intent, "Red-impact actions are disabled by default and require explicit approval")

        if intent.impact == ImpactLevel.AMBER:
            return self._approval(intent, "Amber-impact actions require human approval")

        if intent.requires_authentication and self.config.require_approval_for_authenticated_checks:
            return self._approval(intent, "Authenticated checks require human approval")

        if self.config.safe_mode and intent.budget.max_requests > 10:
            return self._approval(intent, "Safe Mode requires approval for more than 10 requests")

        return PolicyDecision(PolicyDecisionType.ALLOW, "Allowed by policy", intent)

    @staticmethod
    def _host_allowed(host: str, allowed_domains: list[str]) -> bool:
        normalized = [d.lower().rstrip(".") for d in allowed_domains]
        for domain in normalized:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    @staticmethod
    def _deny(intent: ToolIntent, reason: str) -> PolicyDecision:
        return PolicyDecision(PolicyDecisionType.DENY, reason, intent)

    @staticmethod
    def _approval(intent: ToolIntent, reason: str) -> PolicyDecision:
        return PolicyDecision(PolicyDecisionType.REQUIRES_APPROVAL, reason, intent)
