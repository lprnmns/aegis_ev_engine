from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis_ev.audit import AuditLog, redact_value
from aegis_ev.models import AuthorizationProfile, ImpactLevel, PolicyDecision, RequestBudget, ToolIntent
from aegis_ev.policy import PolicyEngine


class AdapterRegistryError(ValueError):
    """Base error for adapter registry failures."""


class DuplicateAdapterError(AdapterRegistryError):
    """Raised when registering an adapter id twice."""


class UnknownAdapterError(AdapterRegistryError):
    """Raised when an adapter id is not registered or is disabled."""


@dataclass(frozen=True)
class AdapterMetadata:
    adapter_id: str
    display_name: str
    description: str
    supported_actions: tuple[str, ...]
    default_impact_level: ImpactLevel
    requires_network: bool
    requires_authentication: bool
    allowed_target_types: tuple[str, ...]
    allowed_argument_schema: dict[str, str]
    timeout_seconds: int
    max_requests: int
    max_concurrency: int
    produces_evidence: bool
    safe_mode_supported: bool
    enabled: bool = True

    def validate(self) -> None:
        if not self.adapter_id.strip():
            raise ValueError("adapter_id is required")
        if not self.supported_actions:
            raise ValueError("supported_actions must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be > 0")


@dataclass(frozen=True)
class ToolActionRequest:
    action_id: str
    adapter_id: str
    target: str
    action: str
    arguments: dict[str, Any]
    requested_impact_level: ImpactLevel | str
    actor: str
    authorization_profile: AuthorizationProfile
    approval_token: str | None = None
    dry_run: bool = True
    requests_used: int = 0


@dataclass(frozen=True)
class ToolActionPlan:
    allowed: bool
    policy_decision: PolicyDecision
    adapter_id: str
    action: str
    normalized_target: str | None
    sanitized_arguments: dict[str, Any]
    impact_level: str
    required_approval: bool
    estimated_budget: dict[str, int]
    audit_event_id: str | None
    command_preview: list[str]
    execution_preview: str
    approval_id: str | None = None
    approval_status: str | None = None
    denial_reason: str | None = None
    decision_code: str = "allowed"
    dry_run: bool = True


class SafeToolAdapter:
    """Planning-only adapter boundary. Adapters accept structured requests, not shell strings."""

    metadata: AdapterMetadata

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        schema = self.metadata.allowed_argument_schema
        extra = sorted(set(arguments) - set(schema))
        if extra:
            return False, f"Unsupported argument(s): {', '.join(extra)}"
        missing = sorted(set(schema) - set(arguments))
        if missing:
            return False, f"Missing required argument(s): {', '.join(missing)}"
        for key, expected in schema.items():
            value = arguments[key]
            if expected == "str" and not isinstance(value, str):
                return False, f"Argument '{key}' must be a string"
            if expected == "int" and not isinstance(value, int):
                return False, f"Argument '{key}' must be an integer"
            if expected == "bool" and not isinstance(value, bool):
                return False, f"Argument '{key}' must be a boolean"
            if expected == "float" and not isinstance(value, (int, float)):
                return False, f"Argument '{key}' must be a number"
        return True, None

    def command_preview(self, request: ToolActionRequest) -> list[str]:
        return ["aegis-ev-adapter", self.metadata.adapter_id, request.action, "--dry-run"]

    def execution_preview(self, request: ToolActionRequest, sanitized_arguments: dict[str, Any]) -> str:
        return f"Dry-run plan for {self.metadata.adapter_id}.{request.action}"


class EchoPlanAdapter(SafeToolAdapter):
    """Harmless adapter used to test framework planning without side effects."""

    metadata = AdapterMetadata(
        adapter_id="echo_plan",
        display_name="Echo Plan Adapter",
        description="Creates a deterministic dry-run plan without network or subprocess execution.",
        supported_actions=("plan",),
        default_impact_level=ImpactLevel.GREEN,
        requires_network=False,
        requires_authentication=False,
        allowed_target_types=("url", "domain"),
        allowed_argument_schema={"message": "str"},
        timeout_seconds=5,
        max_requests=1,
        max_concurrency=1,
        produces_evidence=False,
        safe_mode_supported=True,
    )

    def execution_preview(self, request: ToolActionRequest, sanitized_arguments: dict[str, Any]) -> str:
        return f"Echo dry-run preview: {sanitized_arguments['message']}"


@dataclass
class AdapterRegistry:
    _adapters: dict[str, SafeToolAdapter] = field(default_factory=dict)

    def register(self, adapter: SafeToolAdapter) -> None:
        adapter.metadata.validate()
        if adapter.metadata.adapter_id in self._adapters:
            raise DuplicateAdapterError(f"Duplicate adapter_id: {adapter.metadata.adapter_id}")
        self._adapters[adapter.metadata.adapter_id] = adapter

    def get(self, adapter_id: str) -> SafeToolAdapter:
        try:
            adapter = self._adapters[adapter_id]
        except KeyError as exc:
            raise UnknownAdapterError(f"Unknown adapter_id: {adapter_id}") from exc
        if not adapter.metadata.enabled:
            raise UnknownAdapterError(f"Adapter is disabled: {adapter_id}")
        return adapter

    def list_adapters(self) -> list[AdapterMetadata]:
        return sorted((adapter.metadata for adapter in self._adapters.values()), key=lambda item: item.adapter_id)


class AdapterPlanner:
    """Build policy-gated, auditable dry-run plans for structured adapter requests."""

    def __init__(self, registry: AdapterRegistry, policy_engine: PolicyEngine | None = None) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()

    def plan(self, request: ToolActionRequest, audit_log: AuditLog | None = None) -> ToolActionPlan:
        adapter = self.registry.get(request.adapter_id)
        impact = _impact_or_raw(request.requested_impact_level)
        policy_decision = self.policy_engine.evaluate(
            ToolIntent(
                adapter=request.adapter_id,
                target=request.target,
                impact=impact,
                budget=RequestBudget(max_requests=adapter.metadata.max_requests, timeout_seconds=adapter.metadata.timeout_seconds),
                action_type=request.action,
                requires_authentication=adapter.metadata.requires_authentication,
                requests_used=request.requests_used,
                approval_id=request.approval_token,
                approval_granted=bool(request.approval_token),
            ),
            request.authorization_profile,
        )

        sanitized_arguments = redact_value(request.arguments)
        estimated_budget = {
            "max_requests": adapter.metadata.max_requests,
            "timeout_seconds": adapter.metadata.timeout_seconds,
            "max_concurrency": adapter.metadata.max_concurrency,
        }

        if not policy_decision.allowed:
            return self._make_plan(
                request=request,
                adapter=adapter,
                policy_decision=policy_decision,
                sanitized_arguments=sanitized_arguments,
                estimated_budget=estimated_budget,
                allowed=False,
                command_preview=[],
                execution_preview="Policy denied adapter planning before execution.",
                denial_reason=policy_decision.reason,
                decision_code=policy_decision.code,
                audit_log=audit_log,
            )

        if request.action not in adapter.metadata.supported_actions:
            return self._make_plan(
                request=request,
                adapter=adapter,
                policy_decision=policy_decision,
                sanitized_arguments=sanitized_arguments,
                estimated_budget=estimated_budget,
                allowed=False,
                command_preview=[],
                execution_preview="Unsupported adapter action; no execution plan produced.",
                denial_reason=f"Unsupported action for adapter '{request.adapter_id}': {request.action}",
                decision_code="unsupported_action",
                audit_log=audit_log,
            )

        args_ok, args_reason = adapter.validate_arguments(request.arguments)
        if not args_ok:
            return self._make_plan(
                request=request,
                adapter=adapter,
                policy_decision=policy_decision,
                sanitized_arguments=sanitized_arguments,
                estimated_budget=estimated_budget,
                allowed=False,
                command_preview=[],
                execution_preview="Invalid adapter arguments; no execution plan produced.",
                denial_reason=args_reason or "Invalid adapter arguments",
                decision_code="invalid_arguments",
                audit_log=audit_log,
            )

        return self._make_plan(
            request=request,
            adapter=adapter,
            policy_decision=policy_decision,
            sanitized_arguments=sanitized_arguments,
            estimated_budget=estimated_budget,
            allowed=True,
            command_preview=adapter.command_preview(request),
            execution_preview=redact_value(adapter.execution_preview(request, sanitized_arguments)),
            denial_reason=None,
            decision_code="allowed",
            audit_log=audit_log,
        )

    def _make_plan(
        self,
        *,
        request: ToolActionRequest,
        adapter: SafeToolAdapter,
        policy_decision: PolicyDecision,
        sanitized_arguments: dict[str, Any],
        estimated_budget: dict[str, int],
        allowed: bool,
        command_preview: list[str],
        execution_preview: str,
        denial_reason: str | None,
        decision_code: str,
        audit_log: AuditLog | None,
    ) -> ToolActionPlan:
        audit_event_id = None
        if audit_log is not None:
            event = audit_log.append(
                actor=request.actor,
                action=f"adapter.plan.{request.action}",
                target=request.target,
                details={
                    "action_id": request.action_id,
                    "adapter_id": request.adapter_id,
                    "action": request.action,
                    "arguments": sanitized_arguments,
                    "dry_run": request.dry_run,
                    "policy_decision_code": policy_decision.code,
                    "denial_reason": denial_reason,
                    "command_preview": command_preview,
                    "execution_preview": execution_preview,
                },
                event_type="adapter_plan",
                normalized_target=policy_decision.normalized_target,
                impact_level=_impact_value(request.requested_impact_level),
                decision_code=decision_code,
                allowed=allowed,
                required_approval=policy_decision.required_approval,
            )
            audit_event_id = event.event_id

        return ToolActionPlan(
            allowed=allowed,
            policy_decision=policy_decision,
            adapter_id=request.adapter_id,
            action=request.action,
            normalized_target=policy_decision.normalized_target,
            sanitized_arguments=sanitized_arguments,
            impact_level=_impact_value(request.requested_impact_level),
            required_approval=policy_decision.required_approval,
            estimated_budget=estimated_budget,
            audit_event_id=audit_event_id,
            approval_id=request.approval_token,
            approval_status="approved" if request.approval_token else ("required" if policy_decision.required_approval else None),
            command_preview=command_preview,
            execution_preview=execution_preview,
            denial_reason=denial_reason,
            decision_code=decision_code,
            dry_run=request.dry_run,
        )


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(EchoPlanAdapter())
    return registry


def _impact_or_raw(value: ImpactLevel | str) -> ImpactLevel | str:
    try:
        return ImpactLevel(value)
    except ValueError:
        return value


def _impact_value(value: ImpactLevel | str) -> str:
    if isinstance(value, ImpactLevel):
        return value.value
    return str(value)
