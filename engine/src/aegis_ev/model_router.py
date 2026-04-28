from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .ai_contracts import (
    build_ai_audit_event,
    build_planner_prompt_packet,
    build_reporter_prompt_packet,
    build_verifier_prompt_packet,
    evidence_from_ai_validation,
    validate_planner_output,
    validate_reporter_output,
    validate_verifier_output,
)
from .audit import AuditEvent, AuditLog, GENESIS_HASH, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


PROVIDER_TYPES = {"account_cli", "api", "local", "mock", "proxy", "unknown"}
AUTH_MODES = {"account_auth", "api_key", "local", "mock", "none", "unknown"}
ROLES = {"planner", "policy_reviewer", "remediation_advisor", "reporter", "verifier"}
VALIDATION_STATUS = {"failed", "not_validated", "passed"}


@dataclass(frozen=True)
class ModelProviderProfile:
    provider_id: str
    display_name: str
    provider_type: str
    auth_mode: str
    supported_roles: tuple[str, ...]
    supported_capabilities: tuple[str, ...]
    default_model_alias: str | None = None
    max_context_tokens: int | None = None
    supports_structured_output: bool = True
    supports_tool_calling: bool = False
    supports_streaming: bool = False
    supports_local_only: bool = True
    requires_network: bool = False
    requires_api_key: bool = False
    requires_account_auth: bool = False
    enabled: bool = False
    safe_for_local_tests: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_type", self.provider_type if self.provider_type in PROVIDER_TYPES else "unknown")
        object.__setattr__(self, "auth_mode", self.auth_mode if self.auth_mode in AUTH_MODES else "unknown")
        object.__setattr__(self, "supported_roles", _safe_tuple(self.supported_roles))
        object.__setattr__(self, "supported_capabilities", _safe_tuple(self.supported_capabilities))
        object.__setattr__(self, "metadata", redact_value(self.metadata))
        if self.provider_type != "mock" and self.enabled:
            raise ValueError("only mock providers may be enabled in TASK-023")
        if self.requires_api_key and self.safe_for_local_tests:
            raise ValueError("API-key providers cannot be safe_for_local_tests")
        if self.requires_account_auth and self.safe_for_local_tests:
            raise ValueError("account-auth providers cannot be safe_for_local_tests")

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ModelCapability:
    capability_id: str
    role: str
    supports_planning: bool = False
    supports_verification: bool = False
    supports_reporting: bool = False
    supports_remediation: bool = False
    supports_policy_review: bool = False
    supports_json_output: bool = True
    supports_guardrail_validation: bool = True
    limitations: tuple[str, ...] = field(default_factory=tuple)
    allowed_context_types: tuple[str, ...] = field(default_factory=tuple)
    forbidden_context_types: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ModelRoutingPolicy:
    policy_id: str
    default_provider_id: str
    allowed_provider_ids: tuple[str, ...]
    denied_provider_ids: tuple[str, ...]
    role_provider_preferences: dict[str, tuple[str, ...]]
    allow_api_key_providers: bool = False
    allow_account_auth_providers: bool = False
    allow_network_providers: bool = False
    require_mock_for_tests: bool = True
    require_structured_output: bool = True
    require_guardrail_validation: bool = True
    max_context_items: int = 200
    redaction_required: bool = True
    human_review_required_for_roles: tuple[str, ...] = ("planner", "verifier", "reporter")
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_provider_ids", _safe_tuple(self.allowed_provider_ids))
        object.__setattr__(self, "denied_provider_ids", _safe_tuple(self.denied_provider_ids))
        object.__setattr__(
            self,
            "role_provider_preferences",
            {str(role): tuple(str(item) for item in values) for role, values in self.role_provider_preferences.items()},
        )
        object.__setattr__(self, "human_review_required_for_roles", _safe_tuple(self.human_review_required_for_roles))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ModelRequestEnvelope:
    request_id: str
    created_at_utc: str
    role: str
    contract_id: str
    context_packet_id: str
    provider_id: str
    model_alias: str | None
    prompt_packet: dict[str, Any]
    expected_response_schema: dict[str, Any]
    safety_constraints: tuple[str, ...]
    redaction_applied: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ModelResponseEnvelope:
    response_id: str
    created_at_utc: str
    request_id: str
    provider_id: str
    role: str
    raw_response: dict[str, Any] | None
    parsed_response: dict[str, Any]
    validation_status: str
    validation_errors: tuple[str, ...]
    guardrail_actions: tuple[str, ...]
    human_review_required: bool
    evidence_ids: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "validation_status", self.validation_status if self.validation_status in VALIDATION_STATUS else "not_validated")
        object.__setattr__(self, "raw_response", redact_value(self.raw_response) if self.raw_response is not None else None)
        object.__setattr__(self, "parsed_response", redact_value(self.parsed_response))
        object.__setattr__(self, "validation_errors", _safe_tuple(self.validation_errors))
        object.__setattr__(self, "guardrail_actions", _safe_tuple(self.guardrail_actions))
        object.__setattr__(self, "evidence_ids", _safe_tuple(self.evidence_ids))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


def default_provider_profiles() -> dict[str, ModelProviderProfile]:
    return {
        "mock_safe_provider": ModelProviderProfile(
            provider_id="mock_safe_provider",
            display_name="Offline Mock Provider",
            provider_type="mock",
            auth_mode="mock",
            supported_roles=("planner", "verifier", "reporter"),
            supported_capabilities=("json_output", "guardrail_validation", "offline_fixture_response"),
            default_model_alias="mock-safe-v1",
            max_context_tokens=16000,
            enabled=True,
            safe_for_local_tests=True,
            metadata={"runtime_execution": "mock_only", "provider_credentials": False},
        ),
        "future_account_cli_provider": ModelProviderProfile(
            provider_id="future_account_cli_provider",
            display_name="Future Account CLI Provider",
            provider_type="account_cli",
            auth_mode="account_auth",
            supported_roles=("planner", "verifier", "reporter"),
            supported_capabilities=("json_output",),
            supports_local_only=False,
            requires_network=True,
            requires_account_auth=True,
            enabled=False,
            safe_for_local_tests=False,
            metadata={"future_profile": True, "runtime_execution": "disabled"},
        ),
        "future_api_provider": ModelProviderProfile(
            provider_id="future_api_provider",
            display_name="Future BYOK API Provider",
            provider_type="api",
            auth_mode="api_key",
            supported_roles=("planner", "verifier", "reporter"),
            supported_capabilities=("json_output",),
            supports_local_only=False,
            requires_network=True,
            requires_api_key=True,
            enabled=False,
            safe_for_local_tests=False,
            metadata={"future_profile": True, "runtime_execution": "disabled"},
        ),
    }


def default_routing_policy() -> ModelRoutingPolicy:
    return ModelRoutingPolicy(
        policy_id="model_routing_policy_mock_only_v1",
        default_provider_id="mock_safe_provider",
        allowed_provider_ids=("mock_safe_provider",),
        denied_provider_ids=("future_account_cli_provider", "future_api_provider"),
        role_provider_preferences={
            "planner": ("mock_safe_provider",),
            "verifier": ("mock_safe_provider",),
            "reporter": ("mock_safe_provider",),
        },
        metadata={"live_provider_execution": False, "mock_only": True},
    )


class MockModelProvider:
    def __init__(self, responses: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.responses = {key: dict(value) for key, value in (responses or _default_mock_responses()).items()}

    def generate(self, request: ModelRequestEnvelope, *, fixture_key: str | None = None) -> dict[str, Any]:
        key = fixture_key or request.role
        if key not in self.responses:
            raise ValueError(f"unknown mock response fixture: {key}")
        return dict(self.responses[key])


class ModelRouter:
    def __init__(
        self,
        providers: Mapping[str, ModelProviderProfile] | None = None,
        policy: ModelRoutingPolicy | None = None,
        mock_provider: MockModelProvider | None = None,
    ) -> None:
        self.providers = dict(providers or default_provider_profiles())
        self.policy = policy or default_routing_policy()
        self.mock_provider = mock_provider or MockModelProvider()

    def register_provider(self, profile: ModelProviderProfile) -> None:
        if profile.provider_id in self.providers:
            raise ValueError(f"duplicate provider_id: {profile.provider_id}")
        self.providers[profile.provider_id] = profile

    def list_provider_profiles(self) -> list[ModelProviderProfile]:
        return [self.providers[key] for key in sorted(self.providers)]

    def select_provider(self, role: str, *, provider_id: str | None = None) -> ModelProviderProfile:
        if role not in ROLES:
            raise ValueError(f"unsupported role: {role}")
        candidates = [provider_id] if provider_id else list(self.policy.role_provider_preferences.get(role, ())) + [self.policy.default_provider_id]
        for candidate in candidates:
            if not candidate:
                continue
            profile = self.providers.get(str(candidate))
            if profile and self._provider_allowed(profile, role):
                return profile
        raise ValueError(f"no allowed provider for role: {role}")

    def build_request_envelope(self, payload: Mapping[str, Any]) -> ModelRequestEnvelope:
        role = str(payload.get("role") or "planner")
        provider = self.select_provider(role, provider_id=payload.get("provider_id"))
        packet = _packet_for_role(role, payload.get("prompt_packet") or payload)
        context = packet["context_packet"]
        contract = packet["contract"]
        return ModelRequestEnvelope(
            request_id=_stable_id("model_request", role, provider.provider_id, context.get("context_packet_id"), packet),
            created_at_utc=str(payload.get("created_at_utc") or datetime.now(timezone.utc).isoformat()),
            role=role,
            contract_id=str(contract["contract_id"]),
            context_packet_id=str(context["context_packet_id"]),
            provider_id=provider.provider_id,
            model_alias=payload.get("model_alias") or provider.default_model_alias,
            prompt_packet=packet,
            expected_response_schema=packet["expected_response_schema"],
            safety_constraints=tuple(packet["context_packet"].get("safety_constraints", [])),
            redaction_applied=True,
            metadata={"live_model_call": False, "provider_api_call": False, "browser_account_auth": False},
        )

    def execute_mock_request(self, request: ModelRequestEnvelope | Mapping[str, Any], *, fixture_key: str | None = None) -> ModelResponseEnvelope:
        envelope = request if isinstance(request, ModelRequestEnvelope) else _request_from_dict(request)
        provider = self.providers.get(envelope.provider_id)
        if provider is None:
            raise ValueError(f"unknown provider_id: {envelope.provider_id}")
        if provider.provider_type != "mock":
            raise ValueError("live provider execution is denied in TASK-023")
        parsed = self.mock_provider.generate(envelope, fixture_key=fixture_key)
        return self.validate_response_envelope(envelope, parsed)

    def validate_response_envelope(self, request: ModelRequestEnvelope | Mapping[str, Any], parsed_response: Mapping[str, Any]) -> ModelResponseEnvelope:
        envelope = request if isinstance(request, ModelRequestEnvelope) else _request_from_dict(request)
        existing_evidence_ids = _collect_context_evidence_ids(envelope.prompt_packet)
        validator_payload = {"output": dict(parsed_response), "existing_evidence_ids": existing_evidence_ids}
        if envelope.role == "planner":
            validation = validate_planner_output(validator_payload)
        elif envelope.role == "verifier":
            validation = validate_verifier_output(validator_payload)
        elif envelope.role == "reporter":
            validation = validate_reporter_output(validator_payload)
        else:
            raise ValueError(f"unsupported role for response validation: {envelope.role}")
        evidence = evidence_from_ai_validation(validation)
        status = "passed" if validation.valid else "failed"
        return ModelResponseEnvelope(
            response_id=_stable_id("model_response", envelope.request_id, envelope.provider_id, parsed_response, validation.to_dict()),
            created_at_utc=datetime.now(timezone.utc).isoformat(),
            request_id=envelope.request_id,
            provider_id=envelope.provider_id,
            role=envelope.role,
            raw_response=None,
            parsed_response=dict(parsed_response),
            validation_status=status,
            validation_errors=validation.errors,
            guardrail_actions=validation.blocked_actions,
            human_review_required=validation.human_review_required,
            evidence_ids=(evidence.evidence_id,),
            metadata={
                "validation": validation.to_dict(),
                "evidence": evidence.to_dict(),
                "chain_of_thought_stored": False,
                "live_model_call": False,
            },
        )

    def _provider_allowed(self, profile: ModelProviderProfile, role: str) -> bool:
        if profile.provider_id in self.policy.denied_provider_ids:
            return False
        if self.policy.allowed_provider_ids and profile.provider_id not in self.policy.allowed_provider_ids:
            return False
        if role not in profile.supported_roles:
            return False
        if not profile.enabled:
            return False
        if self.policy.require_mock_for_tests and profile.provider_type != "mock":
            return False
        if profile.requires_api_key and not self.policy.allow_api_key_providers:
            return False
        if profile.requires_account_auth and not self.policy.allow_account_auth_providers:
            return False
        if profile.requires_network and not self.policy.allow_network_providers:
            return False
        if self.policy.require_structured_output and not profile.supports_structured_output:
            return False
        return True


def list_model_providers(payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    router = _router_from_payload(payload or {})
    return {"providers": [profile.to_dict() for profile in router.list_provider_profiles()], "policy": router.policy.to_dict()}


def build_model_request_envelope(payload: Mapping[str, Any]) -> ModelRequestEnvelope:
    return _router_from_payload(payload).build_request_envelope(payload)


def route_model_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    router = _router_from_payload(payload)
    role = str(payload.get("role") or "planner")
    provider = router.select_provider(role, provider_id=payload.get("provider_id"))
    request = router.build_request_envelope(payload)
    return {"provider": provider.to_dict(), "request_envelope": request.to_dict(), "routing_policy": router.policy.to_dict()}


def execute_mock_model_request(payload: Mapping[str, Any]) -> ModelResponseEnvelope:
    router = _router_from_payload(payload)
    request_payload = payload.get("request_envelope") or payload.get("request") or payload
    if isinstance(request_payload, Mapping) and "request_id" in request_payload:
        request = _request_from_dict(request_payload)
    else:
        request = router.build_request_envelope(payload)
    return router.execute_mock_request(request, fixture_key=payload.get("fixture_key"))


def validate_model_response_envelope(payload: Mapping[str, Any]) -> ModelResponseEnvelope:
    router = _router_from_payload(payload)
    request_payload = payload.get("request_envelope") or payload.get("request")
    parsed = payload.get("parsed_response") or payload.get("response") or payload.get("output")
    if not isinstance(request_payload, Mapping):
        raise ValueError("request_envelope is required")
    if not isinstance(parsed, Mapping):
        raise ValueError("parsed_response is required")
    return router.validate_response_envelope(_request_from_dict(request_payload), parsed)


def evidence_from_model_routing(item: Mapping[str, Any] | ModelRequestEnvelope | ModelResponseEnvelope) -> EvidenceRecord:
    data = item.to_dict() if hasattr(item, "to_dict") else dict(item)
    provider_id = str(data.get("provider_id") or data.get("provider", {}).get("provider_id") or "unknown")
    role = str(data.get("role") or data.get("request_envelope", {}).get("role") or "unknown")
    status = str(data.get("validation_status") or "not_validated")
    return EvidenceRecord(
        evidence_type=EvidenceType.MANUAL_NOTE,
        source_type=EvidenceSourceType.MODEL_ROUTER,
        source_id=str(data.get("request_id") or data.get("response_id") or _stable_id("model_router", data)),
        title="Model router record",
        summary=f"Model router {role} record for provider {provider_id}; validation status: {status}.",
        structured_data=redact_value(data),
        tags=("model-router", "mock-only", "no-live-model-call"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def build_model_router_audit_event(
    event_type: str,
    *,
    provider_id: str | None = None,
    role: str | None = None,
    metadata: dict[str, Any] | None = None,
    audit_log: AuditLog | None = None,
    previous_hash: str = GENESIS_HASH,
    timestamp_utc: str | None = None,
) -> AuditEvent:
    details = redact_value(metadata or {}) | {
        "provider_id": provider_id,
        "role": role,
        "live_model_call": False,
        "provider_credentials": False,
        "chain_of_thought_stored": False,
    }
    if audit_log is not None:
        return audit_log.append(
            actor="model_router",
            action=event_type,
            target=None,
            details=details,
            event_type=event_type,
            impact_level="green",
            allowed=True,
            required_approval=False,
        )
    return build_ai_audit_event(
        event_type,
        role=role or "unknown",
        metadata=details,
        previous_hash=previous_hash,
        timestamp_utc=timestamp_utc,
    )


def _router_from_payload(payload: Mapping[str, Any]) -> ModelRouter:
    providers_payload = payload.get("providers")
    providers = None
    if isinstance(providers_payload, list):
        providers = {str(item["provider_id"]): ModelProviderProfile(**item) for item in providers_payload if isinstance(item, Mapping)}
    policy_payload = payload.get("routing_policy") or payload.get("policy")
    policy = ModelRoutingPolicy(**policy_payload) if isinstance(policy_payload, Mapping) else None
    mock_responses = payload.get("mock_responses")
    mock = MockModelProvider(mock_responses) if isinstance(mock_responses, Mapping) else None
    return ModelRouter(providers=providers, policy=policy, mock_provider=mock)


def _packet_for_role(role: str, payload: Any) -> dict[str, Any]:
    if isinstance(payload, Mapping) and {"contract", "context_packet", "prompt_template"}.issubset(payload.keys()):
        return redact_value(dict(payload))
    if role == "planner":
        return build_planner_prompt_packet(_object(payload))
    if role == "verifier":
        return build_verifier_prompt_packet(_object(payload))
    if role == "reporter":
        return build_reporter_prompt_packet(_object(payload))
    raise ValueError(f"unsupported role: {role}")


def _request_from_dict(data: Mapping[str, Any]) -> ModelRequestEnvelope:
    return ModelRequestEnvelope(
        request_id=str(data["request_id"]),
        created_at_utc=str(data["created_at_utc"]),
        role=str(data["role"]),
        contract_id=str(data["contract_id"]),
        context_packet_id=str(data["context_packet_id"]),
        provider_id=str(data["provider_id"]),
        model_alias=data.get("model_alias"),
        prompt_packet=dict(data["prompt_packet"]),
        expected_response_schema=dict(data["expected_response_schema"]),
        safety_constraints=tuple(data.get("safety_constraints", [])),
        redaction_applied=bool(data.get("redaction_applied", True)),
        metadata=dict(data.get("metadata", {})),
    )


def _default_mock_responses() -> dict[str, dict[str, Any]]:
    return {
        "planner": {
            "output_id": "mock_planner_output_valid",
            "role": "planner",
            "recommended_steps": [
                {
                    "step_type": "review_evidence",
                    "impact_level": "green",
                    "status": "proposed",
                    "required_approval": False,
                    "rationale": "Review supplied evidence before planning broader validation.",
                    "related_evidence_ids": ["evidence_demo_header_csp"],
                }
            ],
            "blocked_steps": [],
            "approval_required_steps": [],
            "rationale": ["Mock output is limited to safe evidence review."],
            "assumptions": [],
            "uncertainties": ["No live model or tool execution occurred."],
            "required_human_inputs": [],
            "safety_warnings": ["Use deterministic guardrail validation before trusting output."],
            "confidence": "medium",
        },
        "planner_unsafe": {
            "output_id": "mock_planner_output_unsafe",
            "role": "planner",
            "recommended_steps": [
                {
                    "step_type": "external_scanner_execution",
                    "impact_level": "red",
                    "status": "proposed",
                    "required_approval": False,
                    "rationale": "Intentionally invalid fixture for guardrail tests.",
                    "related_evidence_ids": ["evidence_demo_header_csp"],
                }
            ],
            "blocked_steps": [],
            "approval_required_steps": [],
            "rationale": ["Unsafe mock fixture."],
            "assumptions": [],
            "uncertainties": [],
            "required_human_inputs": [],
            "safety_warnings": [],
            "confidence": "low",
        },
        "verifier": {
            "output_id": "mock_verifier_output_valid",
            "role": "verifier",
            "reviewed_findings": [
                {
                    "finding_id": "finding_demo_missing_csp",
                    "status": "candidate",
                    "verification_state": "evidence_backed",
                    "evidence_ids": ["evidence_demo_header_csp"],
                }
            ],
            "accepted_evidence_ids": ["evidence_demo_header_csp"],
            "rejected_claims": [],
            "false_positive_risks": ["Header observations can vary by route."],
            "verification_gaps": ["No post-remediation retest evidence supplied."],
            "recommended_retests": [],
            "human_review_required": True,
            "confidence": "medium",
        },
        "reporter": {
            "output_id": "mock_reporter_output_valid",
            "role": "reporter",
            "executive_summary": "Supplied metadata supports candidate defensive configuration observations.",
            "technical_summary": "Observations are evidence-backed, not verified exploitation.",
            "finding_narratives": [
                {"finding_id": "finding_demo_missing_csp", "status": "candidate", "evidence_ids": ["evidence_demo_header_csp"]}
            ],
            "remediation_summary": "Apply defensive headers through the owner-controlled deployment workflow.",
            "retest_summary": "Retest with safe metadata/header comparison after changes.",
            "limitations": ["No live model, crawler, scanner, fuzzer, or external tool execution occurred."],
            "confidence": "medium",
        },
    }


def _collect_context_evidence_ids(packet: Mapping[str, Any]) -> tuple[str, ...]:
    summary = _object(_object(packet.get("context_packet")).get("evidence_summary"))
    return tuple(item for item in summary.get("evidence_ids", []) if item and item != "<redacted>")


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _safe_tuple(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        return (values,)
    if isinstance(values, tuple | list | set):
        return tuple(sorted({str(item) for item in values}))
    return ()


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
