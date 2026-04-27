from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from .audit import canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


NODE_TYPES = {
    "admin_surface",
    "api_surface",
    "auth_surface",
    "cdn",
    "domain",
    "endpoint",
    "evidence",
    "finding_candidate",
    "framework",
    "hosting",
    "language",
    "missing_control",
    "platform",
    "project",
    "risk_hypothesis",
    "security_control",
    "target",
    "technology",
    "unknown",
    "upload_surface",
    "url",
    "web_server",
}
EDGE_TYPES = {
    "backed_by_evidence",
    "contains",
    "exposes",
    "hosted_on",
    "indicates",
    "missing_control",
    "protected_by",
    "related_to",
    "redirects_to",
    "resolves_to",
    "served_by",
    "supports_hypothesis",
    "unknown",
    "uses",
}
SURFACE_PARTS = ("admin", "dashboard", "login", "auth", "api", "graphql", "account", "billing", "upload")


@dataclass(frozen=True)
class AttackSurfaceNode:
    node_id: str
    node_type: str
    label: str
    normalized_value: str | None = None
    source: str = "supplied"
    confidence: str = "medium"
    severity_hint: str | None = None
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_type", self.node_type if self.node_type in NODE_TYPES else "unknown")
        object.__setattr__(self, "label", _safe_text(self.label))
        object.__setattr__(self, "normalized_value", redact_target(self.normalized_value))
        object.__setattr__(self, "source", _safe_text(self.source))
        object.__setattr__(self, "confidence", self.confidence if self.confidence in {"low", "medium", "high"} else "low")
        object.__setattr__(self, "severity_hint", _safe_text(self.severity_hint))
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))
        object.__setattr__(self, "tags", tuple(sorted({_safe_text(item) for item in self.tags})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class AttackSurfaceEdge:
    edge_id: str
    from_node_id: str
    to_node_id: str
    edge_type: str
    confidence: str = "medium"
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_type", self.edge_type if self.edge_type in EDGE_TYPES else "unknown")
        object.__setattr__(self, "confidence", self.confidence if self.confidence in {"low", "medium", "high"} else "low")
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))
        object.__setattr__(self, "tags", tuple(sorted({_safe_text(item) for item in self.tags})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class AttackSurfaceGraph:
    graph_id: str
    created_at_utc: str
    project_id: str | None
    target_count: int
    endpoint_count: int
    technology_count: int
    control_count: int
    evidence_count: int
    hypothesis_count: int
    nodes: tuple[AttackSurfaceNode, ...]
    edges: tuple[AttackSurfaceEdge, ...]
    risk_summary: dict[str, Any]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "graph_id": self.graph_id,
                "created_at_utc": self.created_at_utc,
                "project_id": self.project_id,
                "target_count": self.target_count,
                "endpoint_count": self.endpoint_count,
                "technology_count": self.technology_count,
                "control_count": self.control_count,
                "evidence_count": self.evidence_count,
                "hypothesis_count": self.hypothesis_count,
                "nodes": [node.to_dict() for node in self.nodes],
                "edges": [edge.to_dict() for edge in self.edges],
                "risk_summary": self.risk_summary,
                "warnings": list(self.warnings),
                "redaction_applied": self.redaction_applied,
                "metadata": self.metadata,
            }
        )

    def serialize(self) -> str:
        return canonical_json(self.to_dict())


def build_attack_surface_graph(payload: Mapping[str, Any]) -> AttackSurfaceGraph:
    warnings: list[str] = []
    nodes: dict[str, AttackSurfaceNode] = {}
    edges: dict[str, AttackSurfaceEdge] = {}
    evidence_ids_seen: set[str] = set()
    project = _object(payload.get("project"))
    project_id = _string(project.get("project_id") or payload.get("project_id")) if project or payload.get("project_id") else None
    created_at = str(payload.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    environment = str((project or {}).get("environment") or payload.get("environment") or "unknown")
    project_node = None
    if project:
        project_node = _add_node(nodes, "project", project.get("name") or project_id or "Project", normalized=project_id, source="project", tags=("project",), metadata={"environment": environment})

    targets = _list(payload.get("targets") or project.get("targets") if project else payload.get("targets"))
    for target in targets:
        target_payload = _object(target)
        if not target_payload:
            warnings.append("ignored_invalid_target")
            continue
        value = _string(target_payload.get("normalized_value") or target_payload.get("value") or target_payload.get("target") or "")
        if not value:
            warnings.append("ignored_target_without_value")
            continue
        node_type = "domain" if target_payload.get("target_type") == "domain" else ("url" if str(value).startswith(("http://", "https://")) else "target")
        node = _add_node(nodes, node_type, target_payload.get("display_name") or value, normalized=value, source="target", evidence_ids=tuple(target_payload.get("evidence_ids", [])), tags=("target", str(target_payload.get("target_type", "unknown"))), metadata={"in_scope": bool(target_payload.get("in_scope", False))})
        evidence_ids_seen.update(node.evidence_ids)
        if project_node:
            _add_edge(edges, project_node.node_id, node.node_id, "contains", tags=("project-target",))
        domain = _domain_from(value)
        if domain:
            domain_node = _add_node(nodes, "domain", domain, normalized=domain, source="target")
            _add_edge(edges, domain_node.node_id, node.node_id, "resolves_to")

    endpoints = tuple(_object(item) for item in _list(payload.get("endpoints") or payload.get("endpoint_inventory")))
    for endpoint in endpoints:
        if not endpoint:
            warnings.append("ignored_invalid_endpoint")
            continue
        path = _string(endpoint.get("path") or endpoint.get("normalized_url") or endpoint.get("url") or "")
        method = _string(endpoint.get("method") or "GET").upper()
        label = f"{method} {path}".strip()
        evidence = tuple(endpoint.get("evidence_ids", (endpoint.get("evidence_id"),)) if endpoint.get("evidence_id") else endpoint.get("evidence_ids", ()))
        node = _add_node(nodes, "endpoint", label, normalized=path, source=str(endpoint.get("source_type", "endpoint_inventory")), evidence_ids=evidence, tags=("endpoint", method), metadata={"auth_indicators": endpoint.get("auth_indicators", []), "risk_hints": endpoint.get("risk_hints", [])})
        evidence_ids_seen.update(node.evidence_ids)
        host = endpoint.get("host") or _domain_from(_string(endpoint.get("normalized_url") or endpoint.get("url") or ""))
        if host:
            domain_node = _add_node(nodes, "domain", host, normalized=host, source="endpoint_inventory")
            _add_edge(edges, domain_node.node_id, node.node_id, "contains", evidence_ids=node.evidence_ids)
        for surface in _surface_nodes(path):
            surface_node = _add_node(nodes, surface[0], surface[1], normalized=surface[1], source="endpoint_inventory", evidence_ids=node.evidence_ids, tags=("surface",))
            _add_edge(edges, node.node_id, surface_node.node_id, "exposes", evidence_ids=node.evidence_ids)

    fetch = _object(payload.get("fetch_result"))
    if fetch:
        target = _string(fetch.get("normalized_target") or fetch.get("target") or "")
        final_url = _string(fetch.get("final_url") or "")
        if target and final_url and target != final_url:
            source_node = _add_node(nodes, "url", target, normalized=target, source="safe_http_fetch")
            target_node = _add_node(nodes, "url", final_url, normalized=final_url, source="safe_http_fetch")
            _add_edge(edges, source_node.node_id, target_node.node_id, "redirects_to", evidence_ids=tuple(fetch.get("evidence_ids", [])))

    header_checks = tuple(_object(item) for item in _list(payload.get("header_checks")))
    for check in header_checks:
        check_id = str(check.get("check_id", ""))
        evidence = tuple(check.get("evidence_ids", (check.get("evidence_id"),)) if check.get("evidence_id") else check.get("evidence_ids", ()))
        if check_id.startswith("missing_") or "Missing" in str(check.get("title", "")):
            control = str(check.get("title") or check_id).removeprefix("Missing ").replace(" header", "")
            node = _add_node(nodes, "missing_control", control, normalized=control.lower(), source="web_header_check", severity_hint=check.get("severity"), evidence_ids=evidence, tags=("missing-control",))
            evidence_ids_seen.update(node.evidence_ids)

    fingerprint = _object(payload.get("technology_fingerprint") or payload.get("fingerprint"))
    if fingerprint:
        for tech in _list(fingerprint.get("detected_technologies")):
            tech_payload = _object(tech)
            if not tech_payload:
                continue
            node_type = _node_type_for_technology(str(tech_payload.get("category", "technology")))
            node = _add_node(nodes, node_type, tech_payload.get("name", "Technology"), normalized=tech_payload.get("name"), source="technology_fingerprint", confidence=str(tech_payload.get("confidence", "medium")), tags=tuple(tech_payload.get("tags", [])), metadata={"category": tech_payload.get("category"), "version": tech_payload.get("version")})
            for evidence_id in fingerprint.get("evidence_ids", []):
                _add_edge(edges, node.node_id, _evidence_node(nodes, evidence_id).node_id, "backed_by_evidence", evidence_ids=(evidence_id,))
                evidence_ids_seen.add(str(evidence_id))
        for control in fingerprint.get("detected_security_controls", []):
            node = _add_node(nodes, "security_control", control, normalized=str(control).lower(), source="technology_fingerprint", tags=("security-control",))
            for evidence_id in fingerprint.get("evidence_ids", []):
                _add_edge(edges, node.node_id, _evidence_node(nodes, evidence_id).node_id, "backed_by_evidence", evidence_ids=(evidence_id,))
        for control in fingerprint.get("detected_missing_controls", []):
            _add_node(nodes, "missing_control", control, normalized=str(control).lower(), source="technology_fingerprint", tags=("missing-control",))
        for hint in fingerprint.get("admin_surface_hints", []):
            _add_node(nodes, "admin_surface", hint, normalized=hint, source="technology_fingerprint", tags=("surface",))
        for hint in fingerprint.get("api_surface_hints", []):
            _add_node(nodes, "api_surface", hint, normalized=hint, source="technology_fingerprint", tags=("surface",))
        for hypothesis in fingerprint.get("risk_hypotheses", []):
            _add_hypothesis(nodes, edges, _object(hypothesis), source="technology_fingerprint")

    for hypothesis in _list(payload.get("risk_hypotheses")):
        _add_hypothesis(nodes, edges, _object(hypothesis), source="risk_hypothesis")

    for evidence in _list(payload.get("evidence")):
        ev = _object(evidence)
        evidence_id = str(ev.get("evidence_id", ""))
        if evidence_id:
            _evidence_node(nodes, evidence_id, metadata={"source_type": ev.get("source_type"), "title": ev.get("title")})
            evidence_ids_seen.add(evidence_id)

    for finding in _list(payload.get("findings")):
        item = _object(finding)
        if not item:
            continue
        node = _add_node(nodes, "finding_candidate", item.get("title", "Candidate finding"), normalized=item.get("finding_id"), source="finding_candidate", confidence=str(item.get("confidence", "medium")), severity_hint=item.get("severity"), evidence_ids=tuple(item.get("evidence_ids", [])), tags=("finding-candidate", str(item.get("status", "candidate"))))
        evidence_ids_seen.update(node.evidence_ids)

    summary = _summary(nodes.values(), endpoints, fingerprint, environment)
    graph_id = _stable_id("graph", project_id, [node.to_dict() for node in sorted(nodes.values(), key=lambda item: item.node_id)], [edge.to_dict() for edge in sorted(edges.values(), key=lambda item: item.edge_id)])
    node_values = tuple(sorted(nodes.values(), key=lambda item: item.node_id))
    edge_values = tuple(sorted(edges.values(), key=lambda item: item.edge_id))
    return AttackSurfaceGraph(
        graph_id=graph_id,
        created_at_utc=created_at,
        project_id=project_id,
        target_count=sum(1 for node in node_values if node.node_type in {"target", "domain", "url"}),
        endpoint_count=sum(1 for node in node_values if node.node_type == "endpoint"),
        technology_count=sum(1 for node in node_values if node.node_type in {"technology", "framework", "language", "platform", "cdn", "hosting", "web_server"}),
        control_count=sum(1 for node in node_values if node.node_type in {"security_control", "missing_control"}),
        evidence_count=sum(1 for node in node_values if node.node_type == "evidence") or len(evidence_ids_seen),
        hypothesis_count=sum(1 for node in node_values if node.node_type == "risk_hypothesis"),
        nodes=node_values,
        edges=edge_values,
        risk_summary=summary,
        warnings=tuple(warnings),
        redaction_applied=True,
        metadata={"environment": environment, "confirmed_findings_created": False},
    )


def evidence_from_attack_surface_graph(graph: AttackSurfaceGraph) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.ATTACK_SURFACE_GRAPH,
        source_id=graph.graph_id,
        target=None,
        normalized_target=None,
        title="Attack surface graph",
        summary=f"Graph contains {len(graph.nodes)} node(s), {len(graph.edges)} edge(s), and {graph.hypothesis_count} risk hypothesis item(s).",
        structured_data=graph.to_dict(),
        tags=("attack-surface-graph", "passive", "no-network"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def attack_surface_report_section(graph: AttackSurfaceGraph) -> dict[str, Any]:
    return {
        "title": "Attack Surface Summary",
        "target_count": graph.target_count,
        "endpoint_count": graph.endpoint_count,
        "technology_count": graph.technology_count,
        "control_count": graph.control_count,
        "hypothesis_count": graph.hypothesis_count,
        "key_technologies": graph.risk_summary.get("technologies_by_category", {}),
        "key_surfaces": graph.risk_summary.get("surface_hints", {}),
        "missing_controls": graph.risk_summary.get("missing_security_controls", []),
        "risk_hypotheses": graph.risk_summary.get("risk_hypotheses_by_confidence", {}),
        "evidence_coverage": graph.risk_summary.get("evidence_coverage_count", 0),
    }


def _add_node(nodes: dict[str, AttackSurfaceNode], node_type: str, label: Any, *, normalized: Any = None, source: str = "supplied", confidence: str = "medium", severity_hint: Any = None, evidence_ids: tuple[str, ...] = (), tags: tuple[str, ...] = (), metadata: dict[str, Any] | None = None) -> AttackSurfaceNode:
    safe_label = _safe_text(label)
    safe_normalized = redact_target(normalized) if normalized is not None else None
    node_id = _stable_id("node", node_type, safe_normalized or safe_label, source)
    node = AttackSurfaceNode(node_id=node_id, node_type=node_type, label=safe_label, normalized_value=safe_normalized, source=source, confidence=confidence, severity_hint=severity_hint, evidence_ids=evidence_ids, tags=tags, metadata=metadata or {})
    if node_id in nodes:
        existing = nodes[node_id]
        merged = AttackSurfaceNode(node_id=node_id, node_type=existing.node_type, label=existing.label, normalized_value=existing.normalized_value, source=existing.source, confidence=_max_confidence(existing.confidence, node.confidence), severity_hint=existing.severity_hint or node.severity_hint, evidence_ids=existing.evidence_ids + node.evidence_ids, tags=existing.tags + node.tags, metadata=existing.metadata | node.metadata)
        nodes[node_id] = merged
        return merged
    nodes[node_id] = node
    return node


def _add_edge(edges: dict[str, AttackSurfaceEdge], from_node: str, to_node: str, edge_type: str, *, confidence: str = "medium", evidence_ids: tuple[str, ...] = (), tags: tuple[str, ...] = (), metadata: dict[str, Any] | None = None) -> AttackSurfaceEdge:
    edge_id = _stable_id("edge", from_node, to_node, edge_type)
    edge = AttackSurfaceEdge(edge_id=edge_id, from_node_id=from_node, to_node_id=to_node, edge_type=edge_type, confidence=confidence, evidence_ids=evidence_ids, tags=tags, metadata=metadata or {})
    edges[edge_id] = edge
    return edge


def _add_hypothesis(nodes: dict[str, AttackSurfaceNode], edges: dict[str, AttackSurfaceEdge], item: dict[str, Any], *, source: str) -> None:
    if not item:
        return
    evidence_ids = tuple(item.get("related_evidence_ids", []))
    node = _add_node(nodes, "risk_hypothesis", item.get("title", "Risk hypothesis"), normalized=item.get("hypothesis_id"), source=source, confidence=str(item.get("confidence", "medium")), severity_hint=item.get("required_impact_level"), evidence_ids=evidence_ids, tags=("hypothesis",), metadata={"status": item.get("status", "hypothesis"), "rationale": item.get("rationale"), "suggested_safe_next_step": item.get("suggested_safe_next_step")})
    for evidence_id in evidence_ids:
        ev = _evidence_node(nodes, evidence_id)
        _add_edge(edges, node.node_id, ev.node_id, "backed_by_evidence", evidence_ids=(evidence_id,))


def _evidence_node(nodes: dict[str, AttackSurfaceNode], evidence_id: str, metadata: dict[str, Any] | None = None) -> AttackSurfaceNode:
    return _add_node(nodes, "evidence", str(evidence_id), normalized=str(evidence_id), source="evidence", confidence="high", tags=("evidence",), metadata=metadata or {})


def _summary(nodes: Any, endpoints: tuple[dict[str, Any], ...], fingerprint: dict[str, Any], environment: str) -> dict[str, Any]:
    node_list = list(nodes)
    endpoints_by_method: dict[str, int] = {}
    endpoints_by_source: dict[str, int] = {}
    technologies_by_category: dict[str, int] = {}
    hypotheses_by_confidence: dict[str, int] = {}
    missing = sorted({node.label for node in node_list if node.node_type == "missing_control"})
    for endpoint in endpoints:
        method = str(endpoint.get("method", "GET")).upper()
        endpoints_by_method[method] = endpoints_by_method.get(method, 0) + 1
        source = str(endpoint.get("source_type", "unknown"))
        endpoints_by_source[source] = endpoints_by_source.get(source, 0) + 1
    for node in node_list:
        if node.node_type in {"technology", "framework", "language", "platform", "cdn", "hosting", "web_server"}:
            category = str(node.metadata.get("category") or node.node_type)
            technologies_by_category[category] = technologies_by_category.get(category, 0) + 1
        if node.node_type == "risk_hypothesis":
            hypotheses_by_confidence[node.confidence] = hypotheses_by_confidence.get(node.confidence, 0) + 1
    surface_hints = {
        "admin": sum(1 for node in node_list if node.node_type == "admin_surface"),
        "auth": sum(1 for node in node_list if node.node_type == "auth_surface"),
        "api": sum(1 for node in node_list if node.node_type == "api_surface"),
        "upload": sum(1 for node in node_list if node.node_type == "upload_surface"),
    }
    priority_hints = _priority_hints(node_list, fingerprint, environment)
    return redact_value(
        {
            "targets_by_type": _count_by(node_list, "node_type", {"target", "domain", "url"}),
            "endpoints_by_method": dict(sorted(endpoints_by_method.items())),
            "endpoints_by_source": dict(sorted(endpoints_by_source.items())),
            "technologies_by_category": dict(sorted(technologies_by_category.items())),
            "missing_security_controls": missing,
            "surface_hints": surface_hints,
            "risk_hypotheses_by_confidence": dict(sorted(hypotheses_by_confidence.items())),
            "evidence_coverage_count": sum(1 for node in node_list if node.evidence_ids or node.node_type == "evidence"),
            "candidate_finding_count": sum(1 for node in node_list if node.node_type == "finding_candidate"),
            "priority_hints": priority_hints,
        }
    )


def _priority_hints(nodes: list[AttackSurfaceNode], fingerprint: dict[str, Any], environment: str) -> list[dict[str, str]]:
    missing = {node.label for node in nodes if node.node_type == "missing_control"}
    has_admin = any(node.node_type in {"admin_surface", "auth_surface"} for node in nodes)
    has_api = any(node.node_type == "api_surface" for node in nodes)
    hints: list[dict[str, str]] = []
    priority = "high" if environment == "production" else "medium"
    if missing and has_admin:
        hints.append({"priority": priority, "title": "Missing controls overlap with admin/auth surface", "status": "priority_hint"})
    if has_api:
        hints.append({"priority": priority if environment == "production" else "low", "title": "API surface should be reviewed for intended authorization", "status": "priority_hint"})
    if any(node.metadata.get("version") for node in nodes if node.node_type in {"technology", "framework", "web_server"}):
        hints.append({"priority": "medium" if environment == "production" else "low", "title": "Explicit technology version disclosure", "status": "priority_hint"})
    if "source_map_reference_hint" in tuple((fingerprint or {}).get("asset_hints", [])):
        hints.append({"priority": "low", "title": "Source map reference hint supplied", "status": "priority_hint"})
    return hints


def _surface_nodes(path: str) -> tuple[tuple[str, str], ...]:
    lowered = path.lower()
    nodes: list[tuple[str, str]] = []
    if any(part in lowered for part in ("admin", "dashboard")):
        nodes.append(("admin_surface", path))
    if any(part in lowered for part in ("login", "auth", "account", "billing")):
        nodes.append(("auth_surface", path))
    if any(part in lowered for part in ("api", "graphql")):
        nodes.append(("api_surface", path))
    if "upload" in lowered:
        nodes.append(("upload_surface", path))
    return tuple(nodes)


def _node_type_for_technology(category: str) -> str:
    return {
        "backend_framework": "framework",
        "cdn": "cdn",
        "frontend_framework": "framework",
        "hosting": "hosting",
        "language": "language",
        "web_server": "web_server",
    }.get(category, "technology")


def _count_by(nodes: list[AttackSurfaceNode], attr: str, allowed: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        value = str(getattr(node, attr))
        if value in allowed:
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _domain_from(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.hostname:
        return parsed.hostname.lower()
    if value and "/" not in value and " " not in value:
        return value.lower()
    return None


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


def _string(value: Any) -> str:
    return str(redact_value(value or "")).strip()


def _safe_text(value: Any) -> str:
    return str(redact_value(value or "")).strip()


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()[:24]


def _max_confidence(a: str, b: str) -> str:
    rank = {"low": 0, "medium": 1, "high": 2}
    return a if rank.get(a, 0) >= rank.get(b, 0) else b
