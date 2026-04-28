from __future__ import annotations

import hashlib
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .audit import AuditEvent, AuditLog, GENESIS_HASH, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence
from .models import AuthorizationProfile, RequestBudget, ToolIntent
from .policy import PolicyEngine


TOOL_TIERS = {"green", "amber", "red"}
GREEN_TIER_TOOL_IDS = (
    "builtin_attack_surface_graph",
    "builtin_passive_fingerprint",
    "builtin_safe_header_analysis",
    "builtin_safe_http_fetch",
    "builtin_vuln_intel_mapping",
    "local_grype_scan_plan",
    "local_semgrep_static_plan",
    "local_syft_sbom_plan",
    "local_trivy_config_plan",
)
BUILTIN_TOOL_IDS = {
    "builtin_attack_surface_graph",
    "builtin_passive_fingerprint",
    "builtin_safe_header_analysis",
    "builtin_safe_http_fetch",
    "builtin_vuln_intel_mapping",
}
RECON_STEP_TOOL_CAPABILITIES = {
    "analyze_headers": "builtin_safe_header_analysis",
    "build_attack_surface_graph": "builtin_attack_surface_graph",
    "fingerprint_technology": "builtin_passive_fingerprint",
    "map_vulnerability_intelligence": "builtin_vuln_intel_mapping",
    "safe_fetch_metadata": "builtin_safe_http_fetch",
}
SHELL_META_CHARS = set(";&|`$<>\n\r")
SECRET_ARGUMENT_KEYS = {"authorization", "cookie", "password", "secret", "session", "token", "api_key", "apikey"}
EXECUTABLE_ARGUMENT_KEYS = {"binary", "cmd", "command", "executable", "path_to_binary"}
NETWORK_ARGUMENT_KEYS = {"domain", "host", "remote", "target_url", "url"}


@dataclass(frozen=True)
class ToolCapability:
    tool_id: str
    display_name: str
    description: str
    category: str
    tier: str = "green"
    default_impact_level: str = "green"
    supported_actions: tuple[str, ...] = field(default_factory=tuple)
    requires_network: bool = False
    requires_target: bool = False
    requires_filesystem: bool = False
    requires_authentication: bool = False
    safe_mode_supported: bool = True
    dry_run_supported: bool = True
    allowed_target_types: tuple[str, ...] = field(default_factory=tuple)
    allowed_argument_schema: dict[str, str] = field(default_factory=dict)
    forbidden_arguments: tuple[str, ...] = field(default_factory=tuple)
    timeout_seconds: int = 5
    max_requests: int = 1
    max_concurrency: int = 1
    output_parser_id: str | None = None
    evidence_output_types: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        tool_id = self.tool_id.strip()
        if not tool_id:
            raise ValueError("tool_id is required")
        if self.tier not in TOOL_TIERS:
            raise ValueError(f"unsupported tool tier: {self.tier}")
        if self.default_impact_level not in {"green", "amber", "red"}:
            raise ValueError("default_impact_level must be green, amber, or red")
        if not self.supported_actions:
            raise ValueError("supported_actions must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be > 0")
        object.__setattr__(self, "tool_id", tool_id)
        object.__setattr__(self, "supported_actions", tuple(sorted({str(item) for item in self.supported_actions if str(item).strip()})))
        object.__setattr__(self, "forbidden_arguments", tuple(sorted({str(item) for item in self.forbidden_arguments})))
        object.__setattr__(self, "allowed_target_types", tuple(sorted({str(item) for item in self.allowed_target_types})))
        object.__setattr__(self, "evidence_output_types", tuple(sorted({str(item) for item in self.evidence_output_types})))
        object.__setattr__(self, "tags", tuple(sorted({str(item) for item in self.tags})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ToolAvailability:
    tool_id: str
    available: bool
    binary_path: str | None
    reason: str
    checked_at_utc: str
    safe_to_execute_now: bool

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ToolPlan:
    plan_id: str
    tool_id: str
    action: str
    target: str | None
    normalized_target: str | None
    impact_level: str
    dry_run: bool
    allowed: bool
    required_approval: bool
    policy_decision: dict[str, Any] | None
    argv_preview: tuple[str, ...]
    execution_preview: str
    sanitized_arguments: dict[str, Any]
    availability: ToolAvailability
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "plan_id": self.plan_id,
                "tool_id": self.tool_id,
                "action": self.action,
                "target": self.target,
                "normalized_target": self.normalized_target,
                "impact_level": self.impact_level,
                "dry_run": self.dry_run,
                "allowed": self.allowed,
                "required_approval": self.required_approval,
                "policy_decision": self.policy_decision,
                "argv_preview": list(self.argv_preview),
                "execution_preview": self.execution_preview,
                "sanitized_arguments": self.sanitized_arguments,
                "availability": self.availability.to_dict(),
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "evidence_ids": list(self.evidence_ids),
                "metadata": self.metadata,
            }
        )

    def serialize(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class ParserContract:
    parser_id: str
    tool_id: str
    input_format: str
    output_evidence_type: str
    supported_fields: tuple[str, ...]
    redaction_rules: tuple[str, ...]
    limitations: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.parser_id.strip():
            raise ValueError("parser_id is required")
        if not self.tool_id.strip():
            raise ValueError("tool_id is required")
        object.__setattr__(self, "supported_fields", tuple(sorted({str(item) for item in self.supported_fields})))
        object.__setattr__(self, "redaction_rules", tuple(sorted({str(item) for item in self.redaction_rules})))
        object.__setattr__(self, "limitations", tuple(sorted({str(item) for item in self.limitations})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ParsedToolResult:
    parser_result_id: str
    parser_id: str
    tool_id: str
    item_count: int
    items: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    candidate_findings: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "parser_result_id": self.parser_result_id,
                "parser_id": self.parser_id,
                "tool_id": self.tool_id,
                "item_count": self.item_count,
                "items": list(self.items),
                "candidate_findings": list(self.candidate_findings),
                "warnings": list(self.warnings),
                "redaction_applied": self.redaction_applied,
                "metadata": self.metadata,
            }
        )


class ToolCapabilityRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, ToolCapability] = {}

    def register(self, capability: ToolCapability) -> ToolCapability:
        if capability.tool_id in self._capabilities:
            raise ValueError(f"duplicate tool_id: {capability.tool_id}")
        self._capabilities[capability.tool_id] = capability
        return capability

    def get(self, tool_id: str) -> ToolCapability:
        try:
            return self._capabilities[tool_id]
        except KeyError as exc:
            raise KeyError(f"unknown tool_id: {tool_id}") from exc

    def list_tools(self) -> list[ToolCapability]:
        return [self._capabilities[key] for key in sorted(self._capabilities)]

    def list_green_tools(self) -> list[ToolCapability]:
        return [item for item in self.list_tools() if item.tier == "green"]

    def list_by_category(self, category: str) -> list[ToolCapability]:
        return [item for item in self.list_tools() if item.category == category]


def default_tool_registry() -> ToolCapabilityRegistry:
    registry = ToolCapabilityRegistry()
    for capability in _default_capabilities():
        registry.register(capability)
    return registry


def check_tool_availability(
    tool_id: str,
    *,
    registry: ToolCapabilityRegistry | None = None,
    now: datetime | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> ToolAvailability:
    reg = registry or default_tool_registry()
    capability = reg.get(tool_id)
    checked_at = (now or datetime.now(timezone.utc)).isoformat()
    if capability.tool_id in BUILTIN_TOOL_IDS:
        return ToolAvailability(
            tool_id=capability.tool_id,
            available=True,
            binary_path=None,
            reason="builtin_capability_available",
            checked_at_utc=checked_at,
            safe_to_execute_now=True,
        )
    binary_name = str(capability.metadata.get("binary_name") or capability.tool_id)
    found = which(binary_name)
    return ToolAvailability(
        tool_id=capability.tool_id,
        available=bool(found),
        binary_path=found,
        reason="planning_only_external_tool" if found else "binary_not_found",
        checked_at_utc=checked_at,
        safe_to_execute_now=False,
    )


def plan_tool_action(
    payload: Mapping[str, Any],
    *,
    authorization_profile: AuthorizationProfile | None = None,
    registry: ToolCapabilityRegistry | None = None,
    now: datetime | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> ToolPlan:
    reg = registry or default_tool_registry()
    tool_id = str(_required(payload, "tool_id"))
    action = str(_required(payload, "action"))
    capability = reg.get(tool_id)
    target = str(payload.get("target", "")).strip() or None
    warnings: list[str] = []
    errors: list[str] = []
    dry_run = bool(payload.get("dry_run", True))
    sanitized_arguments, argument_errors, redaction_applied = _sanitize_arguments(_dict_or_empty(payload.get("arguments")), capability)
    errors.extend(argument_errors)

    if action not in capability.supported_actions:
        errors.append("unsupported_action")
    if not dry_run:
        errors.append("dry_run_required")
    if capability.requires_target and not target:
        errors.append("target_required")
    if target and not _supported_url_scheme(target):
        errors.append("unsupported_target_scheme")
    availability = check_tool_availability(tool_id, registry=reg, now=now, which=which)
    argv_preview = _argv_preview(capability, action, target, sanitized_arguments)
    policy_decision = None
    required_approval = False
    normalized_target = redact_target(target)
    if target and capability.requires_target:
        if authorization_profile is None:
            errors.append("missing_authorization_profile")
        else:
            decision = PolicyEngine().evaluate(
                ToolIntent(
                    adapter=capability.tool_id,
                    target=target,
                    impact=capability.default_impact_level,
                    budget=RequestBudget(max_requests=capability.max_requests, timeout_seconds=capability.timeout_seconds),
                    reason="green-tier tool dry-run planning",
                    action_type=action,
                    requires_authentication=capability.requires_authentication,
                ),
                authorization_profile,
                now=now,
            )
            policy_decision = decision.to_public_dict()
            normalized_target = policy_decision.get("normalized_target") or normalized_target
            required_approval = bool(policy_decision.get("required_approval"))
            if not policy_decision.get("allowed"):
                errors.append(str(policy_decision.get("decision_code", "policy_denied")))
    if capability.tool_id not in BUILTIN_TOOL_IDS:
        warnings.append("external_tool_planning_only")
        errors.append("external_tool_execution_disabled")
    allowed = not errors and dry_run and availability.safe_to_execute_now
    execution_preview = (
        "Dry-run plan only; no tool execution will occur."
        if allowed
        else "Denied dry-run plan; no tool execution will occur."
    )
    plan = ToolPlan(
        plan_id=_stable_id("tool_plan", tool_id, action, target, sanitized_arguments, errors, warnings),
        tool_id=capability.tool_id,
        action=action,
        target=redact_target(target),
        normalized_target=normalized_target,
        impact_level=capability.default_impact_level,
        dry_run=True,
        allowed=allowed,
        required_approval=required_approval,
        policy_decision=policy_decision,
        argv_preview=argv_preview,
        execution_preview=execution_preview,
        sanitized_arguments=sanitized_arguments,
        availability=availability,
        warnings=tuple(sorted(set(warnings))),
        errors=tuple(sorted(set(errors))),
        metadata={
            "capability_category": capability.category,
            "planning_only": True,
            "tool_execution": False,
            "shell": False,
            "redaction_applied": redaction_applied,
        },
    )
    return plan


def default_parser_contracts() -> dict[str, ParserContract]:
    contracts = [
        ParserContract(
            parser_id="safe_header_check_output",
            tool_id="builtin_safe_header_analysis",
            input_format="aegis_json",
            output_evidence_type="web_header_check",
            supported_fields=("checks", "findings", "evidence"),
            redaction_rules=("header_secret_values", "tokens", "cookies"),
            limitations=("supplied-data only", "candidate findings only"),
        ),
        ParserContract(
            parser_id="technology_fingerprint_output",
            tool_id="builtin_passive_fingerprint",
            input_format="aegis_json",
            output_evidence_type="technology_fingerprint",
            supported_fields=("detected_technologies", "risk_hypotheses"),
            redaction_rules=("sensitive_headers", "tokens", "cookies"),
            limitations=("passive metadata only", "no asset fetching"),
        ),
        ParserContract(
            parser_id="attack_surface_graph_output",
            tool_id="builtin_attack_surface_graph",
            input_format="aegis_json",
            output_evidence_type="attack_surface_graph",
            supported_fields=("nodes", "edges", "risk_summary"),
            redaction_rules=("targets", "tokens", "cookies"),
            limitations=("graph from supplied data only",),
        ),
        ParserContract(
            parser_id="vuln_intel_mapping_output",
            tool_id="builtin_vuln_intel_mapping",
            input_format="aegis_json",
            output_evidence_type="vulnerability_intelligence",
            supported_fields=("matches", "summary"),
            redaction_rules=("references", "tokens", "cookies"),
            limitations=("offline knowledge only", "no vulnerability confirmation"),
        ),
        ParserContract(
            parser_id="semgrep_like_static_finding",
            tool_id="local_semgrep_static_plan",
            input_format="sample_json",
            output_evidence_type="static_analysis_candidate",
            supported_fields=("results",),
            redaction_rules=("paths", "tokens", "cookies"),
            limitations=("sample parser only", "no local tool execution"),
        ),
        ParserContract(
            parser_id="syft_like_sbom",
            tool_id="local_syft_sbom_plan",
            input_format="sample_json",
            output_evidence_type="sbom",
            supported_fields=("artifacts",),
            redaction_rules=("paths", "tokens", "cookies"),
            limitations=("sample parser only", "no local tool execution"),
        ),
        ParserContract(
            parser_id="grype_like_vulnerability",
            tool_id="local_grype_scan_plan",
            input_format="sample_json",
            output_evidence_type="vulnerability_intelligence",
            supported_fields=("matches",),
            redaction_rules=("paths", "tokens", "cookies"),
            limitations=("sample parser only", "no confirmed findings"),
        ),
    ]
    return {contract.parser_id: contract for contract in contracts}


def parse_tool_output(parser_id: str, payload: Mapping[str, Any]) -> ParsedToolResult:
    contracts = default_parser_contracts()
    if parser_id not in contracts:
        raise KeyError(f"unknown parser_id: {parser_id}")
    contract = contracts[parser_id]
    data = redact_value(dict(payload))
    items: list[dict[str, Any]] = []
    candidate_findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if parser_id == "semgrep_like_static_finding":
        for index, result in enumerate(_list(data.get("results"))):
            item = _dict_or_empty(result)
            rule_id = str(item.get("check_id") or item.get("rule_id") or f"rule_{index}")
            path = str(item.get("path") or item.get("file") or "unknown")
            severity = str(item.get("extra", {}).get("severity") or item.get("severity") or "info").lower()
            candidate = {
                "finding_id": _stable_id("finding_candidate", parser_id, rule_id, path),
                "title": f"Static analysis candidate: {rule_id}",
                "status": "candidate",
                "verification_state": "human_review_required",
                "severity": severity if severity in {"info", "low", "medium", "high", "critical"} else "info",
                "source": parser_id,
            }
            items.append({"rule_id": rule_id, "path": path, "severity": candidate["severity"]})
            candidate_findings.append(candidate)
    elif parser_id == "syft_like_sbom":
        for artifact in _list(data.get("artifacts")):
            item = _dict_or_empty(artifact)
            items.append({"name": item.get("name"), "version": item.get("version"), "type": item.get("type")})
    elif parser_id == "grype_like_vulnerability":
        for match in _list(data.get("matches")):
            item = _dict_or_empty(match)
            vuln = _dict_or_empty(item.get("vulnerability"))
            artifact = _dict_or_empty(item.get("artifact"))
            items.append(
                {
                    "vulnerability_id": vuln.get("id"),
                    "severity": str(vuln.get("severity", "unknown")).lower(),
                    "artifact": artifact.get("name"),
                    "status": "knowledge_match_only",
                }
            )
    else:
        for key in contract.supported_fields:
            value = data.get(key)
            if value is not None:
                items.append({key: value})
    result = ParsedToolResult(
        parser_result_id=_stable_id("parser_result", parser_id, items, candidate_findings),
        parser_id=parser_id,
        tool_id=contract.tool_id,
        item_count=len(items),
        items=tuple(items),
        candidate_findings=tuple(candidate_findings),
        warnings=tuple(sorted(set(warnings))),
        metadata={"finding_confirmation_count": 0, "tool_execution": False},
    )
    return result


def evidence_from_tool_availability(availability: ToolAvailability) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.TOOL_ADAPTER,
        source_id=f"{availability.tool_id}:availability",
        title="Tool availability check",
        summary=f"Availability checked for {availability.tool_id}: {availability.available}.",
        structured_data=availability.to_dict(),
        tags=("tool-adapter", "availability", "no-execution"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def evidence_from_tool_plan(plan: ToolPlan) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_PLAN,
        source_type=EvidenceSourceType.TOOL_ADAPTER,
        source_id=plan.plan_id,
        target=plan.target,
        normalized_target=plan.normalized_target,
        title="Green-tier tool dry-run plan",
        summary=f"Dry-run plan for {plan.tool_id}.{plan.action}; allowed={plan.allowed}.",
        structured_data=plan.to_dict(),
        tags=("tool-adapter", "dry-run", "no-execution"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def evidence_from_parsed_tool_result(result: ParsedToolResult) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.TOOL_ADAPTER,
        source_id=result.parser_result_id,
        title="Parsed sample tool output",
        summary=f"Parser {result.parser_id} produced {result.item_count} item(s).",
        structured_data=result.to_dict(),
        tags=("tool-adapter", "parser-contract", "sample-output"),
        confidence=FindingConfidence.LOW,
        redaction_applied=True,
    )


def build_tool_audit_event(
    event_type: str,
    *,
    tool_id: str,
    target: str | None = None,
    plan: ToolPlan | None = None,
    availability: ToolAvailability | None = None,
    parser_result: ParsedToolResult | None = None,
    audit_log: AuditLog | None = None,
    previous_hash: str = GENESIS_HASH,
    actor: str = "tool_adapter_pack",
    timestamp_utc: str | None = None,
) -> AuditEvent:
    metadata = {
        "tool_id": tool_id,
        "plan_id": plan.plan_id if plan else None,
        "parser_result_id": parser_result.parser_result_id if parser_result else None,
        "available": availability.available if availability else None,
        "safe_to_execute_now": availability.safe_to_execute_now if availability else None,
        "argv_preview": list(plan.argv_preview) if plan else None,
        "tool_execution": False,
    }
    if audit_log is not None:
        return audit_log.append(
            actor=actor,
            action=event_type,
            target=target or (plan.target if plan else None),
            details=metadata,
            event_type=event_type,
            normalized_target=plan.normalized_target if plan else None,
            impact_level=plan.impact_level if plan else "green",
            decision_code=(plan.policy_decision or {}).get("decision_code") if plan else event_type,
            allowed=plan.allowed if plan else True,
            required_approval=plan.required_approval if plan else False,
        )
    return AuditLog.build_event(
        AuditLog,
        actor=actor,
        action=event_type,
        target=target or (plan.target if plan else None),
        metadata=metadata,
        previous_hash=previous_hash,
        event_type=event_type,
        normalized_target=plan.normalized_target if plan else None,
        impact_level=plan.impact_level if plan else "green",
        decision_code=(plan.policy_decision or {}).get("decision_code") if plan else event_type,
        allowed=plan.allowed if plan else True,
        required_approval=plan.required_approval if plan else False,
        event_id=_stable_id("audit", event_type, tool_id, plan.plan_id if plan else None),
        timestamp_utc=timestamp_utc,
    )


def _default_capabilities() -> tuple[ToolCapability, ...]:
    return (
        _cap(
            "builtin_safe_http_fetch",
            "Safe HTTP Metadata Fetch",
            "Existing policy-gated safe HTTP metadata/header collection.",
            "builtin_live_safe",
            ("fetch_metadata",),
            requires_network=True,
            requires_target=True,
            output_parser_id="safe_header_check_output",
            evidence_output_types=("safe_http_fetch",),
            tags=("builtin", "policy-gated", "headers"),
            metadata={"adapter_id": "safe_http_fetch"},
        ),
        _cap(
            "builtin_safe_header_analysis",
            "Safe Header Analysis",
            "Existing deterministic supplied-header analysis.",
            "builtin_local_analysis",
            ("analyze_headers",),
            output_parser_id="safe_header_check_output",
            evidence_output_types=("web_header_check",),
            tags=("builtin", "headers", "local"),
            metadata={"adapter_id": "web_header_config_check"},
        ),
        _cap(
            "builtin_passive_fingerprint",
            "Passive Technology Fingerprinting",
            "Existing passive fingerprinting from supplied metadata.",
            "builtin_local_analysis",
            ("fingerprint_from_metadata",),
            output_parser_id="technology_fingerprint_output",
            evidence_output_types=("technology_fingerprint",),
            tags=("builtin", "fingerprint", "local"),
            metadata={"adapter_id": "technology_fingerprint"},
        ),
        _cap(
            "builtin_attack_surface_graph",
            "Attack Surface Graph Builder",
            "Existing graph builder from supplied safe data.",
            "builtin_local_analysis",
            ("build_attack_surface_graph",),
            output_parser_id="attack_surface_graph_output",
            evidence_output_types=("attack_surface_graph",),
            tags=("builtin", "graph", "local"),
            metadata={"adapter_id": "attack_surface_graph"},
        ),
        _cap(
            "builtin_vuln_intel_mapping",
            "Offline Vulnerability Intelligence Mapping",
            "Existing offline knowledge mapping from supplied graph/fingerprint signals.",
            "builtin_local_analysis",
            ("map_vulnerability_intelligence",),
            output_parser_id="vuln_intel_mapping_output",
            evidence_output_types=("vulnerability_intelligence",),
            tags=("builtin", "knowledge", "local"),
            metadata={"adapter_id": "vulnerability_intelligence"},
        ),
        _cap(
            "local_semgrep_static_plan",
            "Semgrep Static Analysis Plan",
            "Planning-only local static analysis capability for future enablement.",
            "local_static_analysis",
            ("plan_static_analysis",),
            requires_filesystem=True,
            output_parser_id="semgrep_like_static_finding",
            evidence_output_types=("static_analysis_candidate",),
            tags=("external", "planning-only", "static-analysis"),
            metadata={"binary_name": "semgrep", "execution_enabled": False},
        ),
        _cap(
            "local_syft_sbom_plan",
            "Syft SBOM Plan",
            "Planning-only local SBOM capability for future enablement.",
            "local_sbom",
            ("plan_sbom_generation",),
            requires_filesystem=True,
            output_parser_id="syft_like_sbom",
            evidence_output_types=("sbom",),
            tags=("external", "planning-only", "sbom"),
            metadata={"binary_name": "syft", "execution_enabled": False},
        ),
        _cap(
            "local_grype_scan_plan",
            "Grype Dependency Knowledge Plan",
            "Planning-only local dependency knowledge mapping capability for future enablement.",
            "local_dependency_intel",
            ("plan_dependency_intel",),
            requires_filesystem=True,
            output_parser_id="grype_like_vulnerability",
            evidence_output_types=("vulnerability_intelligence",),
            tags=("external", "planning-only", "dependency-intel"),
            metadata={"binary_name": "grype", "execution_enabled": False},
        ),
        _cap(
            "local_trivy_config_plan",
            "Trivy Config Analysis Plan",
            "Planning-only local configuration analysis capability for future enablement.",
            "local_config_analysis",
            ("plan_config_analysis",),
            requires_filesystem=True,
            evidence_output_types=("configuration_analysis",),
            tags=("external", "planning-only", "configuration"),
            metadata={"binary_name": "trivy", "execution_enabled": False},
        ),
    )


def _cap(
    tool_id: str,
    display_name: str,
    description: str,
    category: str,
    actions: tuple[str, ...],
    **kwargs: Any,
) -> ToolCapability:
    return ToolCapability(
        tool_id=tool_id,
        display_name=display_name,
        description=description,
        category=category,
        tier="green",
        default_impact_level="green",
        supported_actions=actions,
        safe_mode_supported=True,
        dry_run_supported=True,
        allowed_target_types=("domain", "url", "web", "api"),
        forbidden_arguments=tuple(sorted(EXECUTABLE_ARGUMENT_KEYS | SECRET_ARGUMENT_KEYS)),
        timeout_seconds=5,
        max_requests=1,
        max_concurrency=1,
        **kwargs,
    )


def _sanitize_arguments(arguments: dict[str, Any], capability: ToolCapability) -> tuple[dict[str, Any], list[str], bool]:
    sanitized: dict[str, Any] = {}
    errors: list[str] = []
    redaction_applied = False
    forbidden = set(capability.forbidden_arguments) | EXECUTABLE_ARGUMENT_KEYS
    for key in sorted(arguments):
        raw_key = str(key)
        normalized_key = raw_key.lower().replace("-", "_")
        if normalized_key in forbidden:
            errors.append(f"forbidden_argument:{raw_key}")
            redaction_applied = True
            continue
        value = arguments[key]
        if _contains_shell_meta(value):
            errors.append(f"unsafe_argument_value:{raw_key}")
            redaction_applied = True
            continue
        if capability.tool_id not in BUILTIN_TOOL_IDS and normalized_key in NETWORK_ARGUMENT_KEYS:
            errors.append(f"network_argument_not_allowed:{raw_key}")
            continue
        if any(secret in normalized_key for secret in SECRET_ARGUMENT_KEYS):
            sanitized[raw_key] = "<redacted>"
            redaction_applied = True
        else:
            sanitized[raw_key] = redact_value(value)
            redaction_applied = redaction_applied or sanitized[raw_key] != value
    return sanitized, errors, redaction_applied


def _contains_shell_meta(value: Any) -> bool:
    if isinstance(value, str):
        return any(char in value for char in SHELL_META_CHARS)
    if isinstance(value, list | tuple):
        return any(_contains_shell_meta(item) for item in value)
    if isinstance(value, Mapping):
        return any(_contains_shell_meta(item) for item in value.values())
    return False


def _argv_preview(capability: ToolCapability, action: str, target: str | None, arguments: Mapping[str, Any]) -> tuple[str, ...]:
    if capability.tool_id == "builtin_safe_http_fetch":
        return tuple(item for item in ("aegis-ev", "fetch-http-metadata", "--dry-run", target or "") if item)
    if capability.tool_id == "builtin_safe_header_analysis":
        return ("aegis-ev", "analyze-web-headers", "--dry-run")
    if capability.tool_id == "builtin_passive_fingerprint":
        return ("aegis-ev", "fingerprint-technology", "--dry-run")
    if capability.tool_id == "builtin_attack_surface_graph":
        return ("aegis-ev", "build-attack-surface-graph", "--dry-run")
    if capability.tool_id == "builtin_vuln_intel_mapping":
        return ("aegis-ev", "map-vulnerability-intelligence", "--dry-run")
    binary = str(capability.metadata.get("binary_name") or capability.tool_id)
    if capability.tool_id == "local_semgrep_static_plan":
        return (binary, "--config", str(arguments.get("config", "auto")), "--json", "<workspace>")
    if capability.tool_id == "local_syft_sbom_plan":
        return (binary, "dir:<workspace>", "-o", "json")
    if capability.tool_id == "local_grype_scan_plan":
        return (binary, "sbom:<input>", "-o", "json")
    if capability.tool_id == "local_trivy_config_plan":
        return (binary, "config", "--format", "json", "<workspace>")
    return (capability.tool_id, action, "--dry-run")


def _supported_url_scheme(target: str) -> bool:
    parsed = urlsplit(target)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return False
    return True


def _required(payload: Mapping[str, Any], key: str) -> Any:
    if key not in payload or payload[key] in (None, ""):
        raise ValueError(f"{key} is required")
    return payload[key]


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
