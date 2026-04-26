from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from .models import (
    AuthorizationProfile,
    Environment,
    ImpactLevel,
    PolicyDecision,
    PolicyDecisionType,
    ToolIntent,
)


@dataclass(frozen=True)
class PolicyConfig:
    safe_mode: bool = True
    stop_on_block: bool = True
    allowed_schemes: tuple[str, ...] = ("http", "https")


@dataclass(frozen=True)
class NormalizedTarget:
    url: str
    host: str
    scheme: str


class PolicyEngine:
    """Deterministic enforcement point before any target interaction."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def evaluate(
        self,
        intent: ToolIntent,
        auth: AuthorizationProfile,
        now: datetime | None = None,
    ) -> PolicyDecision:
        now = now or datetime.now(timezone.utc)

        try:
            intent.budget.validate()
        except ValueError as exc:
            return self._deny(intent, "invalid_request_budget", f"Invalid request budget: {exc}")

        target_result = self._normalize_target(intent)
        if isinstance(target_result, PolicyDecision):
            return target_result
        target = target_result

        auth_errors = auth.validation_errors(now)
        if auth_errors:
            return self._deny(
                intent,
                self._auth_error_code(auth_errors[0]),
                auth_errors[0],
                normalized_target=target.url,
            )

        if not self._target_allowed(target.host, auth):
            if self._looks_like_allowed_domain(target.host, auth.allowed_domains):
                return self._deny(
                    intent,
                    "lookalike_domain",
                    f"Target host '{target.host}' resembles an allowed domain but is not in scope",
                    normalized_target=target.url,
                )
            return self._deny(
                intent,
                "target_out_of_scope",
                f"Target host '{target.host}' is outside the authorization scope",
                normalized_target=target.url,
            )

        impact = self._normalize_impact(intent)
        if impact is None:
            return self._deny(
                intent,
                "unknown_impact",
                f"Unknown impact level: {intent.impact}",
                normalized_target=target.url,
            )

        if impact not in auth.normalized_allowed_impacts():
            return self._deny(
                intent,
                "impact_not_allowed",
                f"Impact level '{impact.value}' is not allowed by this authorization profile",
                normalized_target=target.url,
            )

        budget = auth.effective_budget()
        if intent.requests_used >= budget.max_requests:
            return self._deny(
                intent,
                "budget_exceeded",
                "Request budget has been exhausted",
                normalized_target=target.url,
            )

        approval_reason = self._approval_reason(intent, auth, impact)
        if approval_reason is not None:
            if intent.approval_granted and intent.approval_id:
                return self._allow(intent, "Allowed by policy with explicit approval", normalized_target=target.url)
            return self._approval(intent, approval_reason[0], approval_reason[1], normalized_target=target.url)

        return self._allow(intent, "Allowed by policy", normalized_target=target.url)

    def _normalize_target(self, intent: ToolIntent) -> NormalizedTarget | PolicyDecision:
        raw_target = intent.target
        try:
            parsed = urlsplit(raw_target)
        except ValueError as exc:
            return self._deny(intent, "invalid_target", f"Invalid target URL: {exc}")

        scheme = parsed.scheme.lower()
        if scheme not in self.config.allowed_schemes:
            return self._deny(intent, "unsupported_scheme", f"Unsupported URL scheme: {scheme or '<empty>'}")

        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return self._deny(intent, "missing_target_host", "Target host is missing")

        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return self._deny(intent, "invalid_target_host", "Target host is not a valid DNS name")

        try:
            port = parsed.port
        except ValueError as exc:
            return self._deny(intent, "invalid_target_port", f"Invalid target port: {exc}")

        netloc = host if port is None else f"{host}:{port}"
        normalized_path = parsed.path or ""
        normalized_url = urlunsplit((scheme, netloc, normalized_path, "", ""))
        return NormalizedTarget(url=normalized_url, host=host, scheme=scheme)

    @staticmethod
    def _normalize_impact(intent: ToolIntent) -> ImpactLevel | None:
        try:
            return ImpactLevel(intent.impact)
        except ValueError:
            return None

    @staticmethod
    def _target_allowed(target_host: str, auth: AuthorizationProfile) -> bool:
        return PolicyEngine._host_allowed(target_host, auth.allowed_domains) or PolicyEngine._cidr_allowed(
            target_host, auth.allowed_cidrs
        )

    @staticmethod
    def _host_allowed(host: str, allowed_domains: list[str]) -> bool:
        normalized = [domain.lower().rstrip(".") for domain in allowed_domains if domain.strip()]
        for domain in normalized:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    @staticmethod
    def _cidr_allowed(host: str, allowed_cidrs: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in allowed_cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _looks_like_allowed_domain(host: str, allowed_domains: list[str]) -> bool:
        for domain in [d.lower().rstrip(".") for d in allowed_domains if d.strip()]:
            if domain in host and not (host == domain or host.endswith("." + domain)):
                return True
        return False

    def _approval_reason(
        self,
        intent: ToolIntent,
        auth: AuthorizationProfile,
        impact: ImpactLevel,
    ) -> tuple[str, str] | None:
        budget = auth.effective_budget()
        if intent.budget.max_requests > budget.max_requests:
            return ("budget_escalation", "Requested budget exceeds the authorization profile")
        if impact == ImpactLevel.RED:
            return ("red_requires_approval", "Red-impact actions require explicit human approval")
        if intent.requires_authentication and auth.require_approval_for_authenticated_checks:
            return ("authenticated_requires_approval", "Authenticated actions require explicit human approval")
        if impact == ImpactLevel.AMBER and auth.require_approval_for_amber:
            return ("amber_requires_approval", "Amber-impact actions require explicit human approval")
        if (
            impact == ImpactLevel.AMBER
            and auth.normalized_environment() == Environment.PRODUCTION
            and auth.require_approval_for_production_amber
        ):
            return ("production_amber_requires_approval", "Production amber actions require explicit human approval")
        return None

    @staticmethod
    def _auth_error_code(error: str) -> str:
        if "not yet valid" in error:
            return "authorization_not_yet_valid"
        if "expired" in error:
            return "authorization_expired"
        if "scope allowlist" in error:
            return "empty_scope"
        return "invalid_authorization_profile"

    @staticmethod
    def _deny(
        intent: ToolIntent,
        code: str,
        reason: str,
        *,
        normalized_target: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            PolicyDecisionType.DENY,
            reason,
            intent,
            code=code,
            message=reason,
            required_approval=False,
            normalized_target=normalized_target,
        )

    @staticmethod
    def _approval(
        intent: ToolIntent,
        code: str,
        reason: str,
        *,
        normalized_target: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            PolicyDecisionType.REQUIRES_APPROVAL,
            reason,
            intent,
            code=code,
            message=reason,
            required_approval=True,
            normalized_target=normalized_target,
        )

    @staticmethod
    def _allow(intent: ToolIntent, reason: str, *, normalized_target: str | None = None) -> PolicyDecision:
        return PolicyDecision(
            PolicyDecisionType.ALLOW,
            reason,
            intent,
            code="allowed",
            message=reason,
            required_approval=False,
            normalized_target=normalized_target,
        )
