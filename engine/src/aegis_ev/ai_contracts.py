from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .audit import AuditEvent, AuditLog, GENESIS_HASH, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


AI_ROLES = {"planner", "policy_reviewer", "remediation_advisor", "reporter", "unknown", "verifier"}
CONFIDENCE_LEVELS = {"high", "low", "medium"}
IMPACT_LEVELS = {"amber", "green", "red", "unknown"}
PLANNER_ACTIONS = {
    "analyze_headers",
    "build_attack_surface_graph",
    "fingerprint_technology",
    "generate_report",
    "human_review",
    "map_vulnerability_intelligence",
    "retest_after_fix",
    "review_evidence",
    "safe_fetch_metadata",
}
FORBIDDEN_ACTIONS = {
    "autonomous_tool_execution",
    "browser_session_capture",
    "brute_force",
    "credential_testing",
    "crawler_execution",
    "external_scanner_execution",
    "fuzzer_execution",
    "har_replay",
    "intrusive_validation",
    "live_model_call",
    "postman_execution",
    "raw_shell_execution",
}
FORBIDDEN_TERMS = (
    "reverse shell",
    "shell payload",
    "metasploit",
    "rce proof",
    "dump credentials",
    "brute force",
    "password spray",
)
SECRET_KEY_RE = re.compile(r"(api[_-]?key|authorization|bearer|cookie|password|secret|session|set-cookie|token)", re.IGNORECASE)
TOKENISH_RE = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


@dataclass(frozen=True)
class AIContract:
    contract_id: str
    role: str
    version: str
    purpose: str
    allowed_inputs: tuple[str, ...]
    allowed_outputs: tuple[str, ...]
    forbidden_outputs: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    required_guardrails: tuple[str, ...]
    requires_human_review: bool
    max_context_items: int
    redaction_required: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        role = self.role if self.role in AI_ROLES else "unknown"
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "allowed_inputs", _safe_tuple(self.allowed_inputs))
        object.__setattr__(self, "allowed_outputs", _safe_tuple(self.allowed_outputs))
        object.__setattr__(self, "forbidden_outputs", _safe_tuple(self.forbidden_outputs))
        object.__setattr__(self, "allowed_actions", _safe_tuple(self.allowed_actions))
        object.__setattr__(self, "forbidden_actions", _safe_tuple(self.forbidden_actions))
        object.__setattr__(self, "required_guardrails", _safe_tuple(self.required_guardrails))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class AIContextPacket:
    context_packet_id: str
    role: str
    created_at_utc: str
    project_id: str | None
    target: str | None
    normalized_target: str | None
    scope_summary: dict[str, Any]
    policy_summary: dict[str, Any]
    authorization_summary: dict[str, Any]
    attack_surface_summary: dict[str, Any]
    fingerprint_summary: dict[str, Any]
    vulnerability_intel_summary: dict[str, Any]
    recon_plan_summary: dict[str, Any]
    evidence_summary: dict[str, Any]
    finding_summary: dict[str, Any]
    remediation_summary: dict[str, Any]
    retest_summary: dict[str, Any]
    tool_capability_summary: dict[str, Any]
    allowed_action_set: tuple[str, ...]
    forbidden_action_set: tuple[str, ...]
    safety_constraints: tuple[str, ...]
    redaction_applied: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", self.role if self.role in AI_ROLES else "unknown")
        object.__setattr__(self, "target", redact_target(self.target))
        object.__setattr__(self, "normalized_target", redact_target(self.normalized_target))
        for name in (
            "scope_summary",
            "policy_summary",
            "authorization_summary",
            "attack_surface_summary",
            "fingerprint_summary",
            "vulnerability_intel_summary",
            "recon_plan_summary",
            "evidence_summary",
            "finding_summary",
            "remediation_summary",
            "retest_summary",
            "tool_capability_summary",
            "metadata",
        ):
            object.__setattr__(self, name, redact_value(getattr(self, name)))
        object.__setattr__(self, "allowed_action_set", _safe_tuple(self.allowed_action_set))
        object.__setattr__(self, "forbidden_action_set", _safe_tuple(self.forbidden_action_set))
        object.__setattr__(self, "safety_constraints", _safe_tuple(self.safety_constraints))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class AIPromptTemplate:
    template_id: str
    role: str
    version: str
    system_instructions: str
    developer_instructions: str
    input_schema_summary: dict[str, Any]
    output_schema_summary: dict[str, Any]
    safety_constraints: tuple[str, ...]
    refusal_rules: tuple[str, ...]
    required_output_format: str
    examples: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", self.role if self.role in AI_ROLES else "unknown")
        object.__setattr__(self, "system_instructions", _safe_text(self.system_instructions))
        object.__setattr__(self, "developer_instructions", _safe_text(self.developer_instructions))
        object.__setattr__(self, "input_schema_summary", redact_value(self.input_schema_summary))
        object.__setattr__(self, "output_schema_summary", redact_value(self.output_schema_summary))
        object.__setattr__(self, "safety_constraints", _safe_tuple(self.safety_constraints))
        object.__setattr__(self, "refusal_rules", _safe_tuple(self.refusal_rules))
        object.__setattr__(self, "examples", tuple(redact_value(item) for item in self.examples))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class AIValidationResult:
    validation_id: str
    role: str
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    human_review_required: bool
    evidence_ids_referenced: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


def default_ai_contracts() -> dict[str, AIContract]:
    common_inputs = (
        "scope_summary",
        "policy_summary",
        "evidence_summary",
        "finding_summary",
        "recon_plan_summary",
        "attack_surface_summary",
    )
    guardrails = (
        "authorized defensive use only",
        "no autonomous tool execution",
        "no raw shell commands",
        "no provider API calls",
        "no intrusive validation",
        "human approval required for amber or red actions",
        "evidence-backed language only",
        "preserve candidate versus confirmed distinction",
    )
    forbidden_outputs = (
        "exploitability claims without supporting finding status",
        "secret values",
        "raw response bodies",
        "tool execution commands",
        "provider credentials",
        "chain-of-thought",
    )
    return {
        "planner": AIContract(
            contract_id="ai_contract_planner_v1",
            role="planner",
            version="1.0",
            purpose="Recommend safe next steps from deterministic engine context without executing tools.",
            allowed_inputs=common_inputs + ("tool_capability_summary", "vulnerability_intel_summary"),
            allowed_outputs=("recommended_steps", "blocked_steps", "approval_required_steps", "rationale", "uncertainties"),
            forbidden_outputs=forbidden_outputs,
            allowed_actions=tuple(sorted(PLANNER_ACTIONS)),
            forbidden_actions=tuple(sorted(FORBIDDEN_ACTIONS)),
            required_guardrails=guardrails,
            requires_human_review=True,
            max_context_items=200,
            redaction_required=True,
            metadata={"model_invocation": False, "provider_agnostic": True},
        ),
        "verifier": AIContract(
            contract_id="ai_contract_verifier_v1",
            role="verifier",
            version="1.0",
            purpose="Review candidate findings against evidence and identify gaps without confirming unsupported claims.",
            allowed_inputs=common_inputs + ("retest_summary",),
            allowed_outputs=("reviewed_findings", "accepted_evidence_ids", "rejected_claims", "verification_gaps", "recommended_retests"),
            forbidden_outputs=forbidden_outputs,
            allowed_actions=("review_evidence", "human_review", "retest_after_fix"),
            forbidden_actions=tuple(sorted(FORBIDDEN_ACTIONS)),
            required_guardrails=guardrails,
            requires_human_review=True,
            max_context_items=200,
            redaction_required=True,
            metadata={"model_invocation": False, "may_confirm_without_evidence": False},
        ),
        "reporter": AIContract(
            contract_id="ai_contract_reporter_v1",
            role="reporter",
            version="1.0",
            purpose="Draft safe report narratives from supplied evidence and limitations.",
            allowed_inputs=common_inputs + ("remediation_summary", "retest_summary"),
            allowed_outputs=("executive_summary", "technical_summary", "finding_narratives", "remediation_summary", "limitations"),
            forbidden_outputs=forbidden_outputs,
            allowed_actions=("generate_report", "human_review"),
            forbidden_actions=tuple(sorted(FORBIDDEN_ACTIONS)),
            required_guardrails=guardrails,
            requires_human_review=True,
            max_context_items=200,
            redaction_required=True,
            metadata={"model_invocation": False, "no_marketing_exaggeration": True},
        ),
        "remediation_advisor": AIContract(
            contract_id="ai_contract_remediation_advisor_v1",
            role="remediation_advisor",
            version="1.0",
            purpose="Draft defensive remediation text from supplied findings and templates.",
            allowed_inputs=("finding_summary", "remediation_summary", "retest_summary", "evidence_summary"),
            allowed_outputs=("remediation_summary", "verification_steps", "limitations"),
            forbidden_outputs=forbidden_outputs,
            allowed_actions=("human_review", "retest_after_fix"),
            forbidden_actions=tuple(sorted(FORBIDDEN_ACTIONS)),
            required_guardrails=guardrails,
            requires_human_review=True,
            max_context_items=100,
            redaction_required=True,
            metadata={"model_invocation": False},
        ),
        "policy_reviewer": AIContract(
            contract_id="ai_contract_policy_reviewer_v1",
            role="policy_reviewer",
            version="1.0",
            purpose="Summarize policy and approval implications without changing policy decisions.",
            allowed_inputs=("scope_summary", "policy_summary", "authorization_summary", "recon_plan_summary"),
            allowed_outputs=("policy_observations", "approval_questions", "blocked_actions"),
            forbidden_outputs=forbidden_outputs,
            allowed_actions=("human_review",),
            forbidden_actions=tuple(sorted(FORBIDDEN_ACTIONS)),
            required_guardrails=guardrails,
            requires_human_review=True,
            max_context_items=100,
            redaction_required=True,
            metadata={"policy_override_allowed": False, "model_invocation": False},
        ),
    }


def build_planner_prompt_packet(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _build_prompt_packet(payload, "planner")


def build_verifier_prompt_packet(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _build_prompt_packet(payload, "verifier")


def build_reporter_prompt_packet(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _build_prompt_packet(payload, "reporter")


def validate_planner_output(payload: Mapping[str, Any]) -> AIValidationResult:
    return _validate_output(payload, "planner")


def validate_verifier_output(payload: Mapping[str, Any]) -> AIValidationResult:
    return _validate_output(payload, "verifier")


def validate_reporter_output(payload: Mapping[str, Any]) -> AIValidationResult:
    return _validate_output(payload, "reporter")


def validate_ai_output_common(payload: Mapping[str, Any], *, role: str = "unknown") -> AIValidationResult:
    return _validate_output(payload, role)


def evidence_from_ai_validation(result: AIValidationResult) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.MANUAL_NOTE,
        source_type=EvidenceSourceType.AI_CONTRACT_VALIDATION,
        source_id=result.validation_id,
        title="AI contract validation",
        summary=f"AI {result.role} output validation {'passed' if result.valid else 'failed'} with {len(result.errors)} error(s).",
        structured_data=result.to_dict(),
        tags=("ai-contract", "validation", "no-model-call"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def evidence_from_prompt_packet(packet: Mapping[str, Any]) -> EvidenceRecord:
    packet_data = redact_value(dict(packet))
    context = _object(packet_data.get("context_packet"))
    return EvidenceRecord(
        evidence_type=EvidenceType.MANUAL_NOTE,
        source_type=EvidenceSourceType.AI_PLANNER_CONTRACT,
        source_id=str(context.get("context_packet_id") or _stable_id("ai_packet", packet_data)),
        target=context.get("target"),
        normalized_target=context.get("normalized_target"),
        title="AI prompt packet",
        summary=f"Created AI {context.get('role', 'unknown')} prompt packet without model invocation.",
        structured_data=packet_data,
        tags=("ai-contract", "prompt-packet", "no-model-call"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def build_ai_audit_event(
    event_type: str,
    *,
    role: str,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
    audit_log: AuditLog | None = None,
    previous_hash: str = GENESIS_HASH,
    timestamp_utc: str | None = None,
) -> AuditEvent:
    details = redact_value(metadata or {}) | {
        "ai_role": role,
        "model_invocation": False,
        "provider_api_call": False,
        "tool_execution": False,
        "chain_of_thought_stored": False,
    }
    if audit_log is not None:
        return audit_log.append(
            actor="ai_contracts",
            action=event_type,
            target=target,
            details=details,
            event_type=event_type,
            impact_level="green",
            allowed=True,
            required_approval=False,
        )
    base = {
        "event_id": _stable_id("audit", event_type, role, target, details),
        "timestamp_utc": timestamp_utc or datetime.now(timezone.utc).isoformat(),
        "actor": "ai_contracts",
        "event_type": event_type,
        "target": redact_target(target),
        "normalized_target": redact_target(target),
        "action": event_type,
        "impact_level": "green",
        "decision_code": None,
        "allowed": True,
        "required_approval": False,
        "metadata": redact_value(details),
        "previous_hash": previous_hash,
    }
    return AuditEvent(event_hash=AuditLog.compute_event_hash(base), **base)


def _build_prompt_packet(payload: Mapping[str, Any], role: str) -> dict[str, Any]:
    contracts = default_ai_contracts()
    contract = contracts[role]
    context = _context_packet(payload, role, contract)
    template = _prompt_template(role)
    return redact_value(
        {
            "contract": contract.to_dict(),
            "context_packet": context.to_dict(),
            "prompt_template": template.to_dict(),
            "expected_response_schema": _schema_for_role(role),
            "validation_rules": _validation_rules(role),
            "metadata": {"model_invocation": False, "provider_api_call": False, "tool_execution": False},
        }
    )


def _context_packet(payload: Mapping[str, Any], role: str, contract: AIContract) -> AIContextPacket:
    data = redact_value(dict(payload))
    created = str(data.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    target = data.get("target")
    normalized_target = data.get("normalized_target") or target
    summaries = {
        "scope_summary": _summary(data.get("scope_summary") or data.get("scope")),
        "policy_summary": _summary(data.get("policy_summary") or data.get("policy")),
        "authorization_summary": _summary(data.get("authorization_summary") or data.get("authorization_profile")),
        "attack_surface_summary": _summary(data.get("attack_surface_summary") or data.get("attack_surface_graph")),
        "fingerprint_summary": _summary(data.get("fingerprint_summary") or data.get("technology_fingerprint")),
        "vulnerability_intel_summary": _summary(data.get("vulnerability_intel_summary") or data.get("vulnerability_mapping")),
        "recon_plan_summary": _summary(data.get("recon_plan_summary") or data.get("recon_plan")),
        "evidence_summary": _evidence_summary(data.get("evidence") or data.get("evidence_records")),
        "finding_summary": _finding_summary(data.get("findings") or data.get("finding_records")),
        "remediation_summary": _summary(data.get("remediation_summary") or data.get("remediation")),
        "retest_summary": _summary(data.get("retest_summary") or data.get("retest")),
        "tool_capability_summary": _summary(data.get("tool_capability_summary") or data.get("tool_capabilities")),
    }
    allowed = tuple(data.get("allowed_action_set") or contract.allowed_actions)
    forbidden = tuple(sorted(set(data.get("forbidden_action_set") or ()) | set(contract.forbidden_actions)))
    safety = (
        "authorized defensive use only",
        "do not execute tools",
        "do not call model/provider APIs",
        "do not request or reveal secrets",
        "do not overclaim unverified findings",
        "require human approval for amber or red actions",
    )
    return AIContextPacket(
        context_packet_id=_stable_id("ai_context", role, target, normalized_target, summaries, allowed, forbidden),
        role=role,
        created_at_utc=created,
        project_id=data.get("project_id"),
        target=target,
        normalized_target=normalized_target,
        allowed_action_set=allowed,
        forbidden_action_set=forbidden,
        safety_constraints=safety,
        redaction_applied=True,
        metadata={"context_item_count": _context_item_count(summaries), "model_invocation": False},
        **summaries,
    )


def _prompt_template(role: str) -> AIPromptTemplate:
    base_system = (
        "You are an Aegis EV AI contract role operating only on supplied, authorized defensive context. "
        "Return structured JSON only. Do not execute tools, call providers, request secrets, or invent evidence."
    )
    developer = (
        "Use evidence-backed language, preserve candidate versus confirmed distinctions, state uncertainty, "
        "and mark amber/red actions as human approval required. Refuse unsupported or unsafe instructions."
    )
    if role == "planner":
        output = _schema_for_role("planner")
        purpose = "Recommend safe next steps without execution."
    elif role == "verifier":
        output = _schema_for_role("verifier")
        purpose = "Review evidence and verification gaps without unsupported confirmations."
    else:
        output = _schema_for_role("reporter")
        purpose = "Draft concise report sections with limitations and no overclaiming."
    return AIPromptTemplate(
        template_id=f"ai_prompt_{role}_v1",
        role=role,
        version="1.0",
        system_instructions=base_system,
        developer_instructions=f"{purpose} {developer}",
        input_schema_summary={"packet": "AIContextPacket", "contract": "AIContract"},
        output_schema_summary=output,
        safety_constraints=(
            "authorized defensive use only",
            "structured JSON output required",
            "no autonomous tool execution",
            "no intrusive validation",
            "no raw body, cookies, tokens, or auth headers",
            "no provider API calls in this contract layer",
        ),
        refusal_rules=(
        "Refuse instructions for unauthorized testing.",
            "Refuse requests to execute tools or raw shell commands.",
            "Refuse requests to produce intrusive validation instructions.",
            "Refuse requests to approve amber/red actions without human approval.",
        ),
        required_output_format="json_object",
        examples=(_safe_example(role),),
        metadata={"model_invocation": False},
    )


def _validate_output(payload: Mapping[str, Any], role: str) -> AIValidationResult:
    data = dict(payload.get("output") or payload)
    errors: list[str] = []
    warnings: list[str] = []
    blocked: list[str] = []
    role_value = str(data.get("role") or role)
    if role != "unknown" and role_value != role:
        errors.append(f"role must be {role}")
    if role_value not in AI_ROLES:
        errors.append("role is unsupported")

    existing_evidence = {str(item) for item in _list(payload.get("existing_evidence_ids") or payload.get("evidence_ids"))}
    if not existing_evidence:
        existing_evidence = set(_collect_evidence_ids(payload.get("context_packet") or payload.get("context") or {}))
    referenced = tuple(sorted(set(_collect_evidence_ids(data))))
    unknown_evidence = sorted(eid for eid in referenced if existing_evidence and eid not in existing_evidence)
    if unknown_evidence:
        errors.append(f"unknown evidence id(s): {', '.join(unknown_evidence)}")

    unsafe_terms = _unsafe_terms(data)
    if unsafe_terms:
        errors.append(f"forbidden content detected: {', '.join(unsafe_terms)}")
    if _contains_secret(data):
        errors.append("secret-like value detected")

    if role == "planner":
        _validate_planner(data, errors, warnings, blocked)
    elif role == "verifier":
        _validate_verifier(data, errors, warnings)
    elif role == "reporter":
        _validate_reporter(data, errors, warnings)
    else:
        if not data:
            errors.append("output is required")

    valid = not errors
    return AIValidationResult(
        validation_id=_stable_id("ai_validation", role, data, errors, warnings, blocked),
        role=role,
        valid=valid,
        errors=tuple(errors),
        warnings=tuple(warnings),
        blocked_actions=tuple(sorted(set(blocked))),
        human_review_required=bool(data.get("human_review_required") or blocked or errors),
        evidence_ids_referenced=referenced,
        metadata={"model_invocation": False, "provider_api_call": False, "tool_execution": False},
    )


def _validate_planner(data: dict[str, Any], errors: list[str], warnings: list[str], blocked: list[str]) -> None:
    for field_name in ("recommended_steps", "blocked_steps", "approval_required_steps", "rationale"):
        if field_name not in data:
            errors.append(f"{field_name} is required")
    steps = _list(data.get("recommended_steps")) + _list(data.get("blocked_steps")) + _list(data.get("approval_required_steps"))
    if not steps:
        errors.append("at least one planner step is required")
    for raw in steps:
        step = _object(raw)
        action = str(step.get("adapter_action") or step.get("action") or step.get("step_type") or "unknown")
        status = str(step.get("status") or "proposed")
        impact = str(step.get("impact_level") or "unknown")
        approval = bool(step.get("required_approval", False))
        if action not in PLANNER_ACTIONS and status not in {"blocked", "requires_approval"}:
            errors.append(f"unknown action must be blocked: {action}")
        if action in FORBIDDEN_ACTIONS:
            blocked.append(action)
            if status != "blocked":
                errors.append(f"forbidden action must be blocked: {action}")
        if impact in {"amber", "red"} and not approval:
            errors.append(f"{impact} step requires human approval: {action}")
        if impact == "red" and status != "blocked":
            errors.append(f"red step must remain blocked: {action}")
        if not step.get("rationale"):
            errors.append(f"step rationale is required: {action}")
        if not _collect_evidence_ids(step):
            warnings.append(f"step has no evidence reference: {action}")


def _validate_verifier(data: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    for field_name in ("reviewed_findings", "accepted_evidence_ids", "rejected_claims", "verification_gaps", "confidence"):
        if field_name not in data:
            errors.append(f"{field_name} is required")
    for finding in _list(data.get("reviewed_findings")):
        item = _object(finding)
        status = str(item.get("status") or item.get("new_status") or "")
        verification = str(item.get("verification_state") or "")
        evidence_ids = _collect_evidence_ids(item)
        if status == "confirmed" and verification not in {"verified", "evidence_backed"}:
            errors.append("confirmed status requires supporting verification state")
        if status == "confirmed" and not evidence_ids:
            errors.append("confirmed status requires evidence")
    if not _list(data.get("verification_gaps")) and not _list(data.get("accepted_evidence_ids")):
        warnings.append("verifier output should include accepted evidence or verification gaps")


def _validate_reporter(data: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    for field_name in ("executive_summary", "technical_summary", "finding_narratives", "limitations", "confidence"):
        if field_name not in data:
            errors.append(f"{field_name} is required")
    rendered = canonical_json(data).lower()
    if "full coverage" in rendered or "complete penetration test" in rendered or "confirmed exploitability" in rendered:
        errors.append("reporter output overclaims coverage or exploitability")
    if not data.get("limitations"):
        warnings.append("reporter output should include limitations")


def _schema_for_role(role: str) -> dict[str, Any]:
    if role == "planner":
        return {
            "role": "planner",
            "recommended_steps": "array[ReconStep-like]",
            "blocked_steps": "array[ReconStep-like]",
            "approval_required_steps": "array[ReconStep-like]",
            "rationale": "array[string]",
            "assumptions": "array[string]",
            "uncertainties": "array[string]",
            "required_human_inputs": "array[string]",
            "safety_warnings": "array[string]",
            "confidence": "low|medium|high",
        }
    if role == "verifier":
        return {
            "role": "verifier",
            "reviewed_findings": "array[object]",
            "accepted_evidence_ids": "array[string]",
            "rejected_claims": "array[string]",
            "false_positive_risks": "array[string]",
            "verification_gaps": "array[string]",
            "recommended_retests": "array[object]",
            "human_review_required": "boolean",
            "confidence": "low|medium|high",
        }
    return {
        "role": "reporter",
        "executive_summary": "string",
        "technical_summary": "string",
        "finding_narratives": "array[object]",
        "remediation_summary": "string",
        "retest_summary": "string",
        "limitations": "array[string]",
        "confidence": "low|medium|high",
    }


def _validation_rules(role: str) -> tuple[str, ...]:
    rules = [
        "role must match the contract",
        "referenced evidence IDs must exist in supplied context",
        "no secret-like values",
        "no forbidden action requests",
        "no tool execution or provider API calls",
        "no unsupported confirmation or overclaiming",
    ]
    if role == "planner":
        rules.append("amber/red actions require approval and red remains blocked")
    if role == "verifier":
        rules.append("confirmed finding status requires supporting evidence")
    if role == "reporter":
        rules.append("reports must include limitations and avoid full-coverage claims")
    return tuple(rules)


def _safe_example(role: str) -> dict[str, Any]:
    if role == "planner":
        return {
            "role": "planner",
            "recommended_steps": [
                {
                    "step_type": "review_evidence",
                    "impact_level": "green",
                    "status": "proposed",
                    "rationale": "Evidence exists and should be reviewed before broader validation.",
                    "related_evidence_ids": ["evidence_demo_header_csp"],
                }
            ],
            "blocked_steps": [],
            "approval_required_steps": [],
            "rationale": ["Plan is limited to safe supplied-data review."],
            "assumptions": [],
            "uncertainties": [],
            "required_human_inputs": [],
            "safety_warnings": [],
            "confidence": "medium",
        }
    if role == "verifier":
        return {
            "role": "verifier",
            "reviewed_findings": [{"finding_id": "finding_demo_missing_csp", "status": "candidate", "evidence_ids": ["evidence_demo_header_csp"]}],
            "accepted_evidence_ids": ["evidence_demo_header_csp"],
            "rejected_claims": [],
            "false_positive_risks": [],
            "verification_gaps": ["Header observation is evidence-backed but not an exploitation proof."],
            "recommended_retests": [],
            "human_review_required": True,
            "confidence": "medium",
        }
    return {
        "role": "reporter",
        "executive_summary": "A supplied metadata review identified candidate configuration observations.",
        "technical_summary": "Findings are evidence-backed observations, not confirmed exploitability.",
        "finding_narratives": [{"finding_id": "finding_demo_missing_csp", "status": "candidate", "evidence_ids": ["evidence_demo_header_csp"]}],
        "remediation_summary": "Apply defensive header configuration through the owner deployment workflow.",
        "retest_summary": "Retest with safe metadata/header comparison after remediation.",
        "limitations": ["No crawling, scanner execution, or intrusive validation was performed."],
        "confidence": "medium",
    }


def _summary(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, Mapping):
        return redact_value(dict(value))
    if isinstance(value, list | tuple):
        return {"items": redact_value(list(value)), "count": len(value)}
    return {"value": redact_value(value)}


def _evidence_summary(value: Any) -> dict[str, Any]:
    items = [_object(item) for item in _list(value)]
    return {
        "count": len(items),
        "evidence_ids": sorted(str(item.get("evidence_id")) for item in items if item.get("evidence_id")),
        "source_types": sorted({str(item.get("source_type")) for item in items if item.get("source_type")}),
    }


def _finding_summary(value: Any) -> dict[str, Any]:
    items = [_object(item) for item in _list(value)]
    return {
        "count": len(items),
        "finding_ids": sorted(str(item.get("finding_id")) for item in items if item.get("finding_id")),
        "statuses": sorted({str(item.get("status")) for item in items if item.get("status")}),
        "confirmed_count": sum(1 for item in items if item.get("status") == "confirmed"),
        "candidate_count": sum(1 for item in items if item.get("status") == "candidate"),
    }


def _context_item_count(summaries: Mapping[str, Any]) -> int:
    total = 0
    for value in summaries.values():
        if isinstance(value, Mapping) and isinstance(value.get("count"), int):
            total += int(value["count"])
        elif value:
            total += 1
    return total


def _collect_evidence_ids(value: Any) -> tuple[str, ...]:
    found: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, raw in item.items():
                if key in {"evidence_id", "source_evidence_id"} and raw:
                    found.add(str(raw))
                elif key in {"evidence_ids", "accepted_evidence_ids", "related_evidence_ids"}:
                    for eid in _list(raw):
                        if eid:
                            found.add(str(eid))
                else:
                    walk(raw)
        elif isinstance(item, list | tuple):
            for child in item:
                walk(child)

    walk(value)
    return tuple(sorted(found))


def _unsafe_terms(value: Any) -> tuple[str, ...]:
    rendered = canonical_json(value).lower()
    return tuple(term for term in FORBIDDEN_TERMS if term in rendered)


def _contains_secret(value: Any) -> bool:
    def walk(item: Any) -> bool:
        if isinstance(item, Mapping):
            for key, raw in item.items():
                key_text = str(key)
                if key_text.endswith("_id") or key_text.endswith("_ids"):
                    continue
                if SECRET_KEY_RE.search(key_text) and raw not in (None, "", "<redacted>"):
                    return True
                if walk(raw):
                    return True
        elif isinstance(item, list | tuple):
            return any(walk(child) for child in item)
        elif isinstance(item, str):
            return bool(TOKENISH_RE.search(item) and item != "<redacted>")
        return False

    return walk(value)


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _safe_tuple(values: Any) -> tuple[str, ...]:
    return tuple(sorted({str(redact_value(item)) for item in _list(values) or list(values or [])}))


def _safe_text(value: Any) -> str:
    return str(redact_value(value or ""))


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
