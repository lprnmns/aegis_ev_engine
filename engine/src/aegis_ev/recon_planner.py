from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .adapters import AdapterRegistry, UnknownAdapterError, default_registry
from .audit import AuditEvent, AuditLog, GENESIS_HASH, canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence
from .models import AuthorizationProfile, ImpactLevel, RequestBudget, ToolIntent
from .policy import PolicyEngine


PLANNER_MODES = {"conservative", "expanded", "standard"}
STEP_TYPES = {
    "analyze_headers",
    "blocked_intrusive_validation",
    "build_attack_surface_graph",
    "fingerprint_technology",
    "generate_report",
    "human_review",
    "import_api_definition",
    "map_vulnerability_intelligence",
    "retest_after_fix",
    "review_evidence",
    "safe_fetch_metadata",
    "unknown",
}
STEP_STATUSES = {"blocked", "completed", "proposed", "ready", "requires_approval", "skipped"}
PRIORITIES = ("info", "low", "medium", "high", "critical")
GREEN_STEPS = {
    "analyze_headers",
    "build_attack_surface_graph",
    "fingerprint_technology",
    "generate_report",
    "import_api_definition",
    "map_vulnerability_intelligence",
    "retest_after_fix",
    "review_evidence",
    "safe_fetch_metadata",
}
ADAPTER_ACTIONS = {
    "analyze_headers": ("web_header_config_check", "analyze_headers"),
    "build_attack_surface_graph": ("attack_surface_graph", "build_attack_surface_graph"),
    "fingerprint_technology": ("technology_fingerprint", "fingerprint_from_metadata"),
    "import_api_definition": ("api_import", "import_openapi"),
    "map_vulnerability_intelligence": ("vulnerability_intelligence", "map_vulnerability_intelligence"),
    "safe_fetch_metadata": ("safe_http_fetch", "fetch_metadata"),
}


@dataclass(frozen=True)
class ReconStep:
    step_id: str
    title: str
    description: str
    step_type: str
    impact_level: str
    target: str | None
    normalized_target: str | None
    adapter_id: str | None = None
    adapter_action: str | None = None
    input_requirements: tuple[str, ...] = field(default_factory=tuple)
    expected_outputs: tuple[str, ...] = field(default_factory=tuple)
    required_policy_decision: dict[str, Any] = field(default_factory=dict)
    required_approval: bool = False
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    related_graph_node_ids: tuple[str, ...] = field(default_factory=tuple)
    related_knowledge_match_ids: tuple[str, ...] = field(default_factory=tuple)
    related_hypothesis_ids: tuple[str, ...] = field(default_factory=tuple)
    related_evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    rationale: str = ""
    status: str = "proposed"
    priority: str = "low"
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        step_type = self.step_type if self.step_type in STEP_TYPES else "unknown"
        impact = self.impact_level if self.impact_level in {"green", "amber", "red"} else "unknown"
        status = self.status if self.status in STEP_STATUSES else "blocked"
        if impact == "unknown":
            status = "blocked"
        object.__setattr__(self, "step_type", step_type)
        object.__setattr__(self, "impact_level", impact)
        object.__setattr__(self, "target", redact_target(self.target))
        object.__setattr__(self, "normalized_target", redact_target(self.normalized_target))
        object.__setattr__(self, "title", _safe_text(self.title))
        object.__setattr__(self, "description", _safe_text(self.description))
        object.__setattr__(self, "input_requirements", _safe_tuple(self.input_requirements))
        object.__setattr__(self, "expected_outputs", _safe_tuple(self.expected_outputs))
        object.__setattr__(self, "required_policy_decision", redact_value(self.required_policy_decision))
        object.__setattr__(self, "prerequisites", _safe_tuple(self.prerequisites))
        object.__setattr__(self, "related_graph_node_ids", _safe_tuple(self.related_graph_node_ids))
        object.__setattr__(self, "related_knowledge_match_ids", _safe_tuple(self.related_knowledge_match_ids))
        object.__setattr__(self, "related_hypothesis_ids", _safe_tuple(self.related_hypothesis_ids))
        object.__setattr__(self, "related_evidence_ids", _safe_tuple(self.related_evidence_ids))
        object.__setattr__(self, "rationale", _safe_text(self.rationale))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "priority", self.priority if self.priority in PRIORITIES else "low")
        object.__setattr__(self, "tags", _safe_tuple(self.tags))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ReconPlan:
    plan_id: str
    created_at_utc: str
    project_id: str | None
    target: str | None
    normalized_target: str | None
    environment: str
    scope_summary: str
    planner_mode: str
    steps: tuple[ReconStep, ...]
    blocked_steps: tuple[ReconStep, ...]
    approval_required_steps: tuple[ReconStep, ...]
    risk_summary: dict[str, Any]
    evidence_ids: tuple[str, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "plan_id": self.plan_id,
                "created_at_utc": self.created_at_utc,
                "project_id": self.project_id,
                "target": self.target,
                "normalized_target": self.normalized_target,
                "environment": self.environment,
                "scope_summary": self.scope_summary,
                "planner_mode": self.planner_mode,
                "steps": [step.to_dict() for step in self.steps],
                "blocked_steps": [step.to_dict() for step in self.blocked_steps],
                "approval_required_steps": [step.to_dict() for step in self.approval_required_steps],
                "risk_summary": self.risk_summary,
                "evidence_ids": list(self.evidence_ids),
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "redaction_applied": self.redaction_applied,
                "metadata": self.metadata,
            }
        )

    def serialize(self) -> str:
        return canonical_json(self.to_dict())


def plan_safe_recon(
    payload: Mapping[str, Any],
    *,
    authorization_profile: AuthorizationProfile | None = None,
    adapter_registry: AdapterRegistry | None = None,
    audit_log: AuditLog | None = None,
) -> ReconPlan:
    data = dict(payload)
    registry = adapter_registry or default_registry()
    created = str(data.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    planner_mode = str(data.get("planner_mode") or "conservative")
    if planner_mode not in PLANNER_MODES:
        planner_mode = "conservative"
    graph = _object(data.get("attack_surface_graph") or data.get("graph"))
    fingerprint = _object(data.get("technology_fingerprint") or data.get("fingerprint"))
    mapping = _object(data.get("vulnerability_mapping") or data.get("vulnerability_intelligence") or data.get("mapping"))
    project = _object(data.get("project"))
    target = str(data.get("target") or graph.get("target") or fingerprint.get("target") or project.get("target") or "")
    normalized_target = data.get("normalized_target") or fingerprint.get("normalized_target") or _target_from_graph(graph) or target or None
    environment = str(data.get("environment") or graph.get("metadata", {}).get("environment") or project.get("environment") or "staging")
    scope_summary = str(data.get("scope_summary") or _scope_summary(authorization_profile, project))
    context = _context(data, graph, fingerprint, mapping)
    warnings: list[str] = []
    errors: list[str] = []
    proposals: list[dict[str, Any]] = []

    if not context["has_fetch"]:
        proposals.append(_proposal("safe_fetch_metadata", "Collect safe HTTP metadata", "Plan one policy-gated low-impact metadata request.", "green", "high", ("target in scope",), ("status code", "response headers", "no body"), "No fetch evidence is present."))
    if context["has_header_metadata"] and not context["has_header_analysis"]:
        proposals.append(_proposal("analyze_headers", "Analyze supplied headers", "Run deterministic header/config analysis on supplied response metadata.", "green", "high", ("response headers",), ("header check results", "candidate findings"), "Headers are available but no header analysis evidence is present."))
    if context["has_header_metadata"] and not context["has_fingerprint"]:
        proposals.append(_proposal("fingerprint_technology", "Fingerprint passive technology hints", "Analyze supplied headers and capped metadata for conservative technology hints.", "green", "medium", ("response metadata",), ("technology fingerprint", "risk hypotheses"), "Metadata exists but no passive fingerprint is present."))
    if (context["has_fingerprint"] or context["has_endpoints"]) and not context["has_graph"]:
        proposals.append(_proposal("build_attack_surface_graph", "Build attack surface graph", "Connect supplied targets, endpoints, technologies, evidence, and hypotheses.", "green", "medium", ("fingerprint or endpoint inventory",), ("attack surface graph",), "Structured inventory exists but no graph is present."))
    if context["has_graph"] and not context["has_vuln_mapping"]:
        proposals.append(_proposal("map_vulnerability_intelligence", "Map vulnerability intelligence", "Map graph signals to offline local knowledge records.", "green", "medium", ("attack surface graph", "local knowledge records"), ("knowledge matches", "priority hints"), "Graph exists but no vulnerability intelligence mapping is present."))
    if context["has_evidence"] or context["has_findings"]:
        proposals.append(_proposal("generate_report", "Generate report", "Render a deterministic Markdown/JSON report from current evidence and candidate findings.", "green", "medium", ("evidence records",), ("report section", "report artifact"), "Evidence or candidate findings are available for reporting."))
        proposals.append(_proposal("review_evidence", "Review evidence", "Human review of evidence-backed observations before active validation.", "green", "medium", ("evidence records",), ("review notes",), "Evidence exists and should be reviewed before expanding scope."))
    if context["has_retest_candidate"]:
        proposals.append(_proposal("retest_after_fix", "Plan retest after fix", "Record a safe future retest plan without executing validation.", "green", "low", ("candidate finding with retest state",), ("retest plan",), "At least one candidate finding needs future retest planning."))
    if context["has_sensitive_surface_and_missing_control"]:
        proposals.append(_proposal("human_review", "Human review for sensitive surface overlap", "Review admin/auth/API surface hints that overlap with missing controls.", "amber", "high", ("graph", "knowledge matches"), ("approval decision", "review notes"), "Sensitive surface hints and missing controls require human judgement before any active step."))
        proposals.append(_proposal("blocked_intrusive_validation", "Blocked intrusive validation", "Intrusive validation is outside TASK-018 and remains blocked.", "red", "critical", ("explicit future task", "human approval", "policy authorization"), ("blocked step record",), "Planner detected a tempting active path but this task is planning-only."))
    for item in _list(data.get("future_steps")):
        future = _object(item)
        if future:
            proposals.append(_proposal(str(future.get("step_type", "unknown")), str(future.get("title", "Future step")), str(future.get("description", "Future step supplied by caller.")), str(future.get("impact_level", "unknown")), str(future.get("priority", "low")), tuple(future.get("input_requirements", [])), tuple(future.get("expected_outputs", [])), str(future.get("rationale", "Caller supplied future step."))))

    steps = tuple(
        sorted(
            (
                _build_step(
                    proposal,
                    target=target or normalized_target,
                    normalized_target=normalized_target,
                    authorization_profile=authorization_profile,
                    registry=registry,
                    graph=graph,
                    mapping=mapping,
                    context=context,
                    warnings=warnings,
                )
                for proposal in proposals
            ),
            key=lambda step: step.step_id,
        )
    )
    blocked = tuple(step for step in steps if step.status == "blocked")
    approvals = tuple(step for step in steps if step.required_approval or step.status == "requires_approval")
    plan_id = _stable_id("recon_plan", target, normalized_target, environment, planner_mode, [step.to_dict() for step in steps])
    plan = ReconPlan(
        plan_id=plan_id,
        created_at_utc=created,
        project_id=project.get("project_id") or graph.get("project_id"),
        target=target or normalized_target,
        normalized_target=normalized_target,
        environment=environment,
        scope_summary=scope_summary,
        planner_mode=planner_mode,
        steps=steps,
        blocked_steps=blocked,
        approval_required_steps=approvals,
        risk_summary=_risk_summary(steps, context),
        evidence_ids=tuple(sorted(context["evidence_ids"])),
        warnings=tuple(sorted(set(warnings))),
        errors=tuple(errors),
        redaction_applied=True,
        metadata={"planning_only": True, "tool_execution": False, "approval_auto_granted": False},
    )
    if audit_log is not None:
        append_recon_plan_audit_events(plan, audit_log)
    return plan


def append_recon_plan_audit_events(plan: ReconPlan, audit_log: AuditLog | None = None, *, actor: str = "recon_planner") -> tuple[AuditEvent, ...]:
    log = audit_log
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH

    def build(event_type: str, step: ReconStep | None = None) -> AuditEvent:
        nonlocal previous_hash
        metadata = {"plan_id": plan.plan_id}
        if step is not None:
            metadata.update({"step_id": step.step_id, "step_type": step.step_type, "status": step.status})
        event = (
            log.append(
                actor=actor,
                action=event_type,
                target=plan.target,
                details=metadata,
                event_type=event_type,
                normalized_target=plan.normalized_target,
                impact_level=step.impact_level if step else "green",
                decision_code=(step.required_policy_decision or {}).get("decision_code") if step else "recon_plan_created",
                allowed=(step.status not in {"blocked"} if step else True),
                required_approval=step.required_approval if step else bool(plan.approval_required_steps),
            )
            if log is not None
            else AuditLog.build_event(
                AuditLog,
                actor=actor,
                action=event_type,
                target=plan.target,
                metadata=metadata,
                previous_hash=previous_hash,
                event_type=event_type,
                normalized_target=plan.normalized_target,
                impact_level=step.impact_level if step else "green",
                decision_code=(step.required_policy_decision or {}).get("decision_code") if step else "recon_plan_created",
                allowed=(step.status not in {"blocked"} if step else True),
                required_approval=step.required_approval if step else bool(plan.approval_required_steps),
                event_id=_stable_id("audit", plan.plan_id, event_type, step.step_id if step else "plan"),
                timestamp_utc=plan.created_at_utc,
            )
        )
        previous_hash = event.event_hash
        return event

    events.append(build("recon_plan_created"))
    for step in plan.steps:
        if step.status == "blocked":
            events.append(build("recon_step_blocked", step))
        elif step.required_approval:
            events.append(build("recon_step_requires_approval", step))
        else:
            events.append(build("recon_step_proposed", step))
    return tuple(events)


def evidence_from_recon_plan(plan: ReconPlan) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.RECON_PLANNER,
        source_id=plan.plan_id,
        target=plan.target,
        normalized_target=plan.normalized_target,
        title="Safe recon plan",
        summary=(
            f"Recon plan contains {len(plan.steps)} step(s), {len(plan.blocked_steps)} blocked step(s), "
            f"and {len(plan.approval_required_steps)} approval-required step(s)."
        ),
        structured_data=plan.to_dict(),
        tags=("safe-recon-planner", "planning-only", "no-network"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def recon_plan_report_section(plan: ReconPlan) -> dict[str, Any]:
    return {
        "title": "Recon Plan Summary",
        "step_count": len(plan.steps),
        "blocked_step_count": len(plan.blocked_steps),
        "approval_required_step_count": len(plan.approval_required_steps),
        "proposed_safe_next_steps": [step.to_dict() for step in plan.steps if step.status in {"proposed", "ready"}],
        "blocked_or_approval_required_steps": [step.to_dict() for step in plan.steps if step.status in {"blocked", "requires_approval"}],
        "planning_rationale": [step.rationale for step in plan.steps],
        "limitations": [
            "This is a deterministic planning artifact only.",
            "No live tool execution, scanner, crawler, fuzzer, external tool, or intrusive validation was performed.",
        ],
    }


def _build_step(
    proposal: dict[str, Any],
    *,
    target: str | None,
    normalized_target: str | None,
    authorization_profile: AuthorizationProfile | None,
    registry: AdapterRegistry,
    graph: dict[str, Any],
    mapping: dict[str, Any],
    context: dict[str, Any],
    warnings: list[str],
) -> ReconStep:
    step_type = proposal["step_type"] if proposal["step_type"] in STEP_TYPES else "unknown"
    impact = _impact_for(step_type, proposal.get("impact_level", "unknown"))
    adapter_id, adapter_action = ADAPTER_ACTIONS.get(step_type, (None, None))
    related_nodes, related_matches, related_hypotheses = _related_ids(step_type, graph, mapping)
    related_evidence = tuple(sorted(set(context["evidence_ids"])))
    decision = _policy_decision(
        target=target or normalized_target,
        adapter_id=adapter_id or "recon_planner",
        adapter_action=adapter_action or step_type,
        impact=impact,
        authorization_profile=authorization_profile,
    )
    required_approval = bool(decision.get("required_approval"))
    status = "proposed"
    if impact == "unknown":
        status = "blocked"
    elif impact == "red":
        status = "blocked"
        required_approval = False
    elif impact == "amber":
        status = "requires_approval"
        required_approval = True
    elif decision and not decision.get("allowed") and not decision.get("required_approval"):
        status = "blocked"
    elif decision.get("required_approval"):
        status = "requires_approval"
    if adapter_id and adapter_action:
        try:
            adapter = registry.get(adapter_id)
            if adapter_action not in adapter.metadata.supported_actions:
                warnings.append(f"adapter_action_unavailable:{adapter_id}.{adapter_action}")
                status = "blocked"
        except UnknownAdapterError:
            warnings.append(f"adapter_unavailable:{adapter_id}")
            status = "blocked"
    approval_shape = None
    if required_approval:
        approval_shape = {
            "status": "pending",
            "requested_actor_type": "system",
            "action_type": step_type,
            "target": redact_target(target),
            "impact_level": impact,
            "auto_approved": False,
        }
    step_id = _stable_id("recon_step", step_type, impact, target, adapter_id, adapter_action, proposal.get("rationale"), tuple(related_nodes), tuple(related_matches))
    return ReconStep(
        step_id=step_id,
        title=proposal["title"],
        description=proposal["description"],
        step_type=step_type,
        impact_level=impact,
        target=target,
        normalized_target=decision.get("normalized_target") or normalized_target,
        adapter_id=adapter_id,
        adapter_action=adapter_action,
        input_requirements=tuple(proposal.get("input_requirements", ())),
        expected_outputs=tuple(proposal.get("expected_outputs", ())),
        required_policy_decision=decision,
        required_approval=required_approval,
        prerequisites=tuple(proposal.get("prerequisites", ())),
        related_graph_node_ids=tuple(related_nodes),
        related_knowledge_match_ids=tuple(related_matches),
        related_hypothesis_ids=tuple(related_hypotheses),
        related_evidence_ids=related_evidence,
        rationale=proposal["rationale"],
        status=status,
        priority=proposal.get("priority", "low"),
        tags=(step_type, "planning-only"),
        metadata={"approval_request": approval_shape, "tool_execution": False},
    )


def _policy_decision(*, target: str | None, adapter_id: str, adapter_action: str, impact: str, authorization_profile: AuthorizationProfile | None) -> dict[str, Any]:
    if not target:
        return {"allowed": False, "decision_code": "missing_target", "required_approval": False, "normalized_target": None}
    if impact not in {"green", "amber", "red"}:
        return {"allowed": False, "decision_code": "unknown_impact", "required_approval": False, "normalized_target": redact_target(target)}
    if authorization_profile is None:
        return {"allowed": False, "decision_code": "missing_authorization_profile", "required_approval": False, "normalized_target": redact_target(target)}
    decision = PolicyEngine().evaluate(
        ToolIntent(
            adapter=adapter_id,
            target=target,
            impact=impact,
            budget=RequestBudget(max_requests=1, timeout_seconds=5),
            reason="safe recon planning",
            action_type=adapter_action,
            requires_authentication=False,
        ),
        authorization_profile,
    )
    return decision.to_public_dict()


def _context(data: dict[str, Any], graph: dict[str, Any], fingerprint: dict[str, Any], mapping: dict[str, Any]) -> dict[str, Any]:
    evidence = tuple(_object(item) for item in _list(data.get("evidence")))
    findings = tuple(_object(item) for item in _list(data.get("findings")))
    nodes = tuple(_object(item) for item in _list(graph.get("nodes")))
    evidence_ids = {str(item.get("evidence_id")) for item in evidence if item.get("evidence_id")}
    for node in nodes:
        evidence_ids.update(str(item) for item in _list(node.get("evidence_ids")))
    has_fetch = bool(data.get("fetch_result") or _source_present(evidence, "safe_http_fetch"))
    has_header_metadata = bool(data.get("headers") or _object(data.get("fetch_result")).get("headers"))
    has_header_analysis = bool(data.get("header_checks") or _source_present(evidence, "web_header_check"))
    has_fingerprint = bool(fingerprint or _source_present(evidence, "technology_fingerprint"))
    has_endpoints = bool(data.get("endpoints") or data.get("endpoint_inventory") or graph.get("endpoint_count"))
    has_graph = bool(graph.get("graph_id") or nodes)
    has_vuln_mapping = bool(mapping.get("mapping_id") or mapping.get("matches") or _source_present(evidence, "vulnerability_intelligence"))
    has_findings = bool(findings)
    has_retest_candidate = any(str(item.get("status", "")).lower() in {"candidate", "draft", "retest_required"} and str(item.get("retest_status", "not_retested")).lower() in {"not_retested", "retest_required"} for item in findings)
    missing_controls = [node for node in nodes if node.get("node_type") == "missing_control"]
    sensitive_surfaces = [node for node in nodes if node.get("node_type") in {"admin_surface", "api_surface", "auth_surface"}]
    return {
        "has_fetch": has_fetch,
        "has_header_metadata": has_header_metadata,
        "has_header_analysis": has_header_analysis,
        "has_fingerprint": has_fingerprint,
        "has_endpoints": has_endpoints,
        "has_graph": has_graph,
        "has_vuln_mapping": has_vuln_mapping,
        "has_evidence": bool(evidence_ids or evidence),
        "has_findings": has_findings,
        "has_retest_candidate": has_retest_candidate,
        "has_sensitive_surface_and_missing_control": bool(missing_controls and sensitive_surfaces),
        "evidence_ids": tuple(sorted(evidence_ids)),
    }


def _related_ids(step_type: str, graph: dict[str, Any], mapping: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    nodes = tuple(_object(item) for item in _list(graph.get("nodes")))
    matches = tuple(_object(item) for item in _list(mapping.get("matches")))
    node_ids: set[str] = set()
    hypothesis_ids: set[str] = set()
    if step_type in {"human_review", "blocked_intrusive_validation"}:
        for node in nodes:
            if node.get("node_type") in {"admin_surface", "api_surface", "auth_surface", "missing_control"} and node.get("node_id"):
                node_ids.add(str(node["node_id"]))
    for node in nodes:
        if node.get("node_type") == "risk_hypothesis" and node.get("node_id"):
            hypothesis_ids.add(str(node["node_id"]))
    match_ids = {str(match["match_id"]) for match in matches if match.get("match_id")}
    return tuple(sorted(node_ids)), tuple(sorted(match_ids)), tuple(sorted(hypothesis_ids))


def _proposal(step_type: str, title: str, description: str, impact_level: str, priority: str, input_requirements: tuple[str, ...], expected_outputs: tuple[str, ...], rationale: str) -> dict[str, Any]:
    return {
        "step_type": step_type,
        "title": title,
        "description": description,
        "impact_level": impact_level,
        "priority": priority if priority in PRIORITIES else "low",
        "input_requirements": input_requirements,
        "expected_outputs": expected_outputs,
        "rationale": rationale,
    }


def _impact_for(step_type: str, supplied: str) -> str:
    supplied = str(supplied)
    if step_type in GREEN_STEPS:
        return "green"
    if step_type == "human_review":
        return "amber"
    if step_type == "blocked_intrusive_validation":
        return "red"
    if supplied in {"green", "amber", "red"}:
        return supplied
    return "unknown"


def _risk_summary(steps: tuple[ReconStep, ...], context: dict[str, Any]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_impact: dict[str, int] = {}
    for step in steps:
        by_status[step.status] = by_status.get(step.status, 0) + 1
        by_impact[step.impact_level] = by_impact.get(step.impact_level, 0) + 1
    return {
        "steps_by_status": dict(sorted(by_status.items())),
        "steps_by_impact": dict(sorted(by_impact.items())),
        "sensitive_surface_with_missing_control": context["has_sensitive_surface_and_missing_control"],
        "planning_only": True,
        "auto_approved_steps": 0,
    }


def _source_present(evidence: tuple[dict[str, Any], ...], source_type: str) -> bool:
    return any(str(item.get("source_type")) == source_type for item in evidence)


def _target_from_graph(graph: dict[str, Any]) -> str | None:
    for node in _list(graph.get("nodes")):
        item = _object(node)
        if item.get("node_type") in {"url", "target"} and item.get("normalized_value"):
            return str(item["normalized_value"])
    return None


def _scope_summary(auth: AuthorizationProfile | None, project: dict[str, Any]) -> str:
    if auth is not None:
        return f"Allowed domains: {', '.join(sorted(auth.allowed_domains))}"
    if project.get("scope"):
        return "Project scope supplied"
    return "No authorization profile supplied to planner"


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, list):
        return value
    return []


def _safe_tuple(values: Any) -> tuple[str, ...]:
    return tuple(sorted({str(redact_value(item or "")).strip() for item in _list(values) if str(item).strip()}))


def _safe_text(value: Any) -> str:
    return str(redact_value(value or "")).strip()


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
