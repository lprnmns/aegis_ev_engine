from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .audit import canonical_json, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


RECORD_TYPES = {"best_practice", "control", "cve", "cwe", "epss", "kev", "owasp", "unknown"}
PRIORITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCE_VALUES = {"low", "medium", "high"}
SURFACE_NODE_TYPES = {"admin_surface", "api_surface", "auth_surface", "upload_surface"}
CONTROL_NODE_TYPES = {"missing_control", "security_control"}
TECH_NODE_TYPES = {"cdn", "framework", "hosting", "language", "platform", "technology", "web_server"}


@dataclass(frozen=True)
class SecurityKnowledgeRecord:
    record_id: str
    record_type: str
    title: str
    summary: str
    category: str
    severity_hint: str
    confidence: str
    references: tuple[str, ...] = field(default_factory=tuple)
    related_cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    related_owasp_refs: tuple[str, ...] = field(default_factory=tuple)
    affected_technology_patterns: tuple[str, ...] = field(default_factory=tuple)
    affected_surface_patterns: tuple[str, ...] = field(default_factory=tuple)
    detection_signals: tuple[str, ...] = field(default_factory=tuple)
    remediation_summary: str = ""
    safe_next_steps: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.record_type not in RECORD_TYPES:
            raise ValueError(f"invalid record_type: {self.record_type}")
        object.__setattr__(self, "record_id", str(self.record_id).strip())
        object.__setattr__(self, "title", _safe_text(self.title))
        object.__setattr__(self, "summary", _safe_text(self.summary))
        object.__setattr__(self, "category", _safe_text(self.category))
        object.__setattr__(self, "severity_hint", _priority(self.severity_hint))
        object.__setattr__(self, "confidence", self.confidence if self.confidence in CONFIDENCE_VALUES else "low")
        object.__setattr__(self, "references", _safe_tuple(self.references))
        object.__setattr__(self, "related_cwe_ids", _safe_tuple(self.related_cwe_ids))
        object.__setattr__(self, "related_owasp_refs", _safe_tuple(self.related_owasp_refs))
        object.__setattr__(self, "affected_technology_patterns", _safe_tuple(self.affected_technology_patterns))
        object.__setattr__(self, "affected_surface_patterns", _safe_tuple(self.affected_surface_patterns))
        object.__setattr__(self, "detection_signals", _safe_tuple(self.detection_signals))
        object.__setattr__(self, "remediation_summary", _safe_text(self.remediation_summary))
        object.__setattr__(self, "safe_next_steps", _safe_tuple(self.safe_next_steps))
        object.__setattr__(self, "tags", _safe_tuple(self.tags))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {
            "record_id": self.record_id,
            "record_type": self.record_type,
            "title": redact_value(data["title"]),
            "summary": redact_value(data["summary"]),
            "category": redact_value(data["category"]),
            "severity_hint": self.severity_hint,
            "confidence": self.confidence,
            "references": redact_value(data["references"]),
            "related_cwe_ids": redact_value(data["related_cwe_ids"]),
            "related_owasp_refs": redact_value(data["related_owasp_refs"]),
            "affected_technology_patterns": redact_value(data["affected_technology_patterns"]),
            "affected_surface_patterns": redact_value(data["affected_surface_patterns"]),
            "detection_signals": redact_value(data["detection_signals"]),
            "remediation_summary": redact_value(data["remediation_summary"]),
            "safe_next_steps": redact_value(data["safe_next_steps"]),
            "tags": redact_value(data["tags"]),
            "metadata": redact_value(data["metadata"]),
        }


@dataclass(frozen=True)
class KnowledgeMatch:
    match_id: str
    knowledge_record_id: str
    matched_node_ids: tuple[str, ...]
    matched_evidence_ids: tuple[str, ...]
    matched_technology: str | None
    matched_surface: str | None
    match_reason: str
    confidence: str
    priority: str
    severity_hint: str
    recommended_safe_next_step: str
    requires_human_review: bool
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "match_id", str(self.match_id).strip())
        object.__setattr__(self, "knowledge_record_id", str(self.knowledge_record_id).strip())
        object.__setattr__(self, "matched_node_ids", _safe_tuple(self.matched_node_ids))
        object.__setattr__(self, "matched_evidence_ids", _safe_tuple(self.matched_evidence_ids))
        object.__setattr__(self, "matched_technology", _safe_optional(self.matched_technology))
        object.__setattr__(self, "matched_surface", _safe_optional(self.matched_surface))
        object.__setattr__(self, "match_reason", _safe_text(self.match_reason))
        object.__setattr__(self, "confidence", self.confidence if self.confidence in CONFIDENCE_VALUES else "low")
        object.__setattr__(self, "priority", _priority(self.priority))
        object.__setattr__(self, "severity_hint", _priority(self.severity_hint))
        object.__setattr__(self, "recommended_safe_next_step", _safe_text(self.recommended_safe_next_step))
        object.__setattr__(self, "tags", _safe_tuple(self.tags))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {
            "match_id": self.match_id,
            "knowledge_record_id": self.knowledge_record_id,
            "matched_node_ids": list(self.matched_node_ids),
            "matched_evidence_ids": list(self.matched_evidence_ids),
            "matched_technology": redact_value(data["matched_technology"]),
            "matched_surface": redact_value(data["matched_surface"]),
            "match_reason": redact_value(data["match_reason"]),
            "confidence": self.confidence,
            "priority": self.priority,
            "severity_hint": self.severity_hint,
            "recommended_safe_next_step": redact_value(data["recommended_safe_next_step"]),
            "requires_human_review": self.requires_human_review,
            "tags": redact_value(data["tags"]),
            "metadata": redact_value(data["metadata"]),
        }


@dataclass(frozen=True)
class VulnerabilityIntelligenceMapping:
    mapping_id: str
    created_at_utc: str
    source_graph_id: str | None
    match_count: int
    matches: tuple[KnowledgeMatch, ...]
    priority_summary: dict[str, int]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "created_at_utc": self.created_at_utc,
            "source_graph_id": self.source_graph_id,
            "match_count": self.match_count,
            "matches": [match.to_dict() for match in self.matches],
            "priority_summary": redact_value(self.priority_summary),
            "warnings": redact_value(list(self.warnings)),
            "redaction_applied": self.redaction_applied,
            "metadata": redact_value(self.metadata),
        }

    def serialize(self) -> str:
        return canonical_json(self.to_dict())


def knowledge_record_from_dict(payload: Mapping[str, Any]) -> SecurityKnowledgeRecord:
    data = dict(payload)
    return SecurityKnowledgeRecord(
        record_id=str(data.get("record_id", "")),
        record_type=str(data.get("record_type", "unknown")),
        title=str(data.get("title", "")),
        summary=str(data.get("summary", "")),
        category=str(data.get("category", "unknown")),
        severity_hint=str(data.get("severity_hint", "info")),
        confidence=str(data.get("confidence", "low")),
        references=tuple(data.get("references", [])),
        related_cwe_ids=tuple(data.get("related_cwe_ids", [])),
        related_owasp_refs=tuple(data.get("related_owasp_refs", [])),
        affected_technology_patterns=tuple(data.get("affected_technology_patterns", [])),
        affected_surface_patterns=tuple(data.get("affected_surface_patterns", [])),
        detection_signals=tuple(data.get("detection_signals", [])),
        remediation_summary=str(data.get("remediation_summary", "")),
        safe_next_steps=tuple(data.get("safe_next_steps", [])),
        tags=tuple(data.get("tags", [])),
        metadata=dict(data.get("metadata", {})),
    )


def load_knowledge_records(payloads: Any) -> tuple[SecurityKnowledgeRecord, ...]:
    if isinstance(payloads, Mapping):
        payloads = payloads.get("records", [])
    if not isinstance(payloads, list):
        raise ValueError("knowledge_records must be a list")
    return tuple(sorted((knowledge_record_from_dict(item) for item in payloads), key=lambda item: item.record_id))


def map_vulnerability_intelligence(payload: Mapping[str, Any]) -> VulnerabilityIntelligenceMapping:
    data = dict(payload)
    records = load_knowledge_records(data.get("knowledge_records", []))
    if not records:
        raise ValueError("knowledge_records are required")
    graph = _object(data.get("attack_surface_graph") or data.get("graph") or {})
    fingerprint = _object(data.get("technology_fingerprint") or data.get("fingerprint") or {})
    environment = str(data.get("environment") or graph.get("metadata", {}).get("environment") or "unknown").lower()
    created = str(data.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    signals = _collect_signals(graph=graph, fingerprint=fingerprint, evidence=data.get("evidence", []))
    matches: list[KnowledgeMatch] = []
    for record in records:
        match = _match_record(record, signals, environment)
        if match:
            matches.append(match)
    ordered = tuple(sorted(matches, key=lambda item: item.match_id))
    priority_summary = {priority: sum(1 for item in ordered if item.priority == priority) for priority in PRIORITIES}
    priority_summary = {key: value for key, value in priority_summary.items() if value}
    mapping_id = _stable_id("vuln_intel", graph.get("graph_id"), [match.to_dict() for match in ordered])
    return VulnerabilityIntelligenceMapping(
        mapping_id=mapping_id,
        created_at_utc=created,
        source_graph_id=graph.get("graph_id"),
        match_count=len(ordered),
        matches=ordered,
        priority_summary=priority_summary,
        warnings=tuple(),
        redaction_applied=True,
        metadata={
            "environment": environment,
            "confirmed_findings_created": False,
            "live_feed_ingestion": False,
            "network_access": False,
            "knowledge_record_count": len(records),
        },
    )


def evidence_from_vulnerability_mapping(mapping: VulnerabilityIntelligenceMapping) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.VULNERABILITY_INTELLIGENCE,
        source_id=mapping.mapping_id,
        title="Vulnerability intelligence mapping",
        summary=f"Mapped supplied attack surface signals to {mapping.match_count} safe knowledge record match(es).",
        structured_data=mapping.to_dict(),
        tags=("vulnerability-intelligence", "offline", "no-network"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def vulnerability_intelligence_report_section(mapping: VulnerabilityIntelligenceMapping) -> dict[str, Any]:
    return {
        "title": "Vulnerability Intelligence Summary",
        "match_count": mapping.match_count,
        "priority_hints": mapping.priority_summary,
        "knowledge_matches": [
            {
                "knowledge_record_id": match.knowledge_record_id,
                "priority": match.priority,
                "confidence": match.confidence,
                "reason": match.match_reason,
                "safe_next_step": match.recommended_safe_next_step,
            }
            for match in mapping.matches
        ],
        "limitations": [
            "Offline knowledge matches are prioritization hints, not vulnerability confirmation.",
            "No live feed lookup, target probing, scanner execution, or intrusive validation was performed.",
        ],
    }


def findings_from_vulnerability_mapping(_mapping: VulnerabilityIntelligenceMapping) -> list[Any]:
    return []


def _collect_signals(*, graph: dict[str, Any], fingerprint: dict[str, Any], evidence: Any) -> dict[str, Any]:
    nodes = tuple(_object(item) for item in _list(graph.get("nodes")))
    evidence_ids = {str(item.get("evidence_id")) for item in _list(evidence) if _object(item).get("evidence_id")}
    missing_controls: list[dict[str, Any]] = []
    surfaces: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    for node in nodes:
        node_type = str(node.get("node_type", "unknown"))
        if node_type == "missing_control":
            missing_controls.append(node)
        if node_type in SURFACE_NODE_TYPES:
            surfaces.append(node)
        if node_type in TECH_NODE_TYPES:
            technologies.append(node)
        if node_type == "risk_hypothesis":
            hypotheses.append(node)
        evidence_ids.update(str(item) for item in _list(node.get("evidence_ids")))
    for control in _list(fingerprint.get("detected_missing_controls")):
        missing_controls.append({"node_id": _stable_id("signal", "missing", control), "label": str(control), "node_type": "missing_control", "confidence": "medium", "evidence_ids": fingerprint.get("evidence_ids", [])})
    for tech in _list(fingerprint.get("detected_technologies")):
        item = _object(tech)
        if item:
            technologies.append({"node_id": _stable_id("signal", "technology", item.get("name"), item.get("category")), "label": item.get("name"), "node_type": "technology", "confidence": item.get("confidence", "medium"), "metadata": {"category": item.get("category"), "version": item.get("version")}, "evidence_ids": fingerprint.get("evidence_ids", [])})
    for hint in _list(fingerprint.get("admin_surface_hints")):
        surfaces.append({"node_id": _stable_id("signal", "admin", hint), "label": str(hint), "node_type": "admin_surface", "confidence": "medium", "evidence_ids": fingerprint.get("evidence_ids", [])})
    for hint in _list(fingerprint.get("api_surface_hints")):
        surfaces.append({"node_id": _stable_id("signal", "api", hint), "label": str(hint), "node_type": "api_surface", "confidence": "medium", "evidence_ids": fingerprint.get("evidence_ids", [])})
    for hypothesis in _list(fingerprint.get("risk_hypotheses")):
        item = _object(hypothesis)
        if item:
            hypotheses.append({"node_id": item.get("hypothesis_id") or _stable_id("signal", "hypothesis", item), "label": item.get("title", "Risk hypothesis"), "node_type": "risk_hypothesis", "confidence": item.get("confidence", "medium"), "evidence_ids": item.get("related_evidence_ids", [])})
            evidence_ids.update(str(item) for item in _list(item.get("related_evidence_ids")))
    asset_hints = tuple(str(item) for item in _list(fingerprint.get("asset_hints")))
    endpoint_hints = tuple(str(item) for item in _list(fingerprint.get("endpoint_hints")))
    return {
        "missing_controls": tuple(missing_controls),
        "surfaces": tuple(surfaces),
        "technologies": tuple(technologies),
        "hypotheses": tuple(hypotheses),
        "asset_hints": asset_hints,
        "endpoint_hints": endpoint_hints,
        "evidence_ids": tuple(sorted(evidence_ids)),
    }


def _match_record(record: SecurityKnowledgeRecord, signals: dict[str, Any], environment: str) -> KnowledgeMatch | None:
    matched_nodes: set[str] = set()
    matched_evidence: set[str] = set()
    matched_technology: str | None = None
    matched_surface: str | None = None
    reasons: list[str] = []
    signal_patterns = tuple(_norm(item) for item in record.detection_signals)
    surface_patterns = tuple(_norm(item) for item in record.affected_surface_patterns)
    technology_patterns = tuple(_norm(item) for item in record.affected_technology_patterns)
    for control in signals["missing_controls"]:
        label = _norm(control.get("label") or control.get("normalized_value"))
        if _matches_any(label, signal_patterns):
            matched_nodes.add(str(control.get("node_id")))
            matched_evidence.update(str(item) for item in _list(control.get("evidence_ids")))
            reasons.append(f"matched missing control: {control.get('label')}")
    for surface in signals["surfaces"]:
        label = _norm(surface.get("label") or surface.get("normalized_value") or surface.get("node_type"))
        node_type = _norm(surface.get("node_type"))
        if _matches_any(label, signal_patterns + surface_patterns) or _matches_any(node_type, signal_patterns + surface_patterns):
            matched_nodes.add(str(surface.get("node_id")))
            matched_surface = str(surface.get("label") or surface.get("node_type"))
            matched_evidence.update(str(item) for item in _list(surface.get("evidence_ids")))
            reasons.append(f"matched surface signal: {matched_surface}")
    for tech in signals["technologies"]:
        label = _norm(tech.get("label") or tech.get("name"))
        category = _norm(_object(tech.get("metadata")).get("category") or tech.get("node_type"))
        if _matches_any(label, signal_patterns + technology_patterns) or _matches_any(category, technology_patterns):
            matched_nodes.add(str(tech.get("node_id")))
            matched_technology = str(tech.get("label") or tech.get("name"))
            matched_evidence.update(str(item) for item in _list(tech.get("evidence_ids")))
            reasons.append(f"matched technology signal: {matched_technology}")
    for hypothesis in signals["hypotheses"]:
        label = _norm(hypothesis.get("label"))
        if _matches_any(label, signal_patterns + surface_patterns + technology_patterns):
            matched_nodes.add(str(hypothesis.get("node_id")))
            matched_evidence.update(str(item) for item in _list(hypothesis.get("evidence_ids")))
            reasons.append(f"matched risk hypothesis: {hypothesis.get('label')}")
    for hint in signals["asset_hints"] + signals["endpoint_hints"]:
        if _matches_any(_norm(hint), signal_patterns + surface_patterns + technology_patterns):
            matched_surface = matched_surface or str(hint)
            reasons.append(f"matched supplied hint: {hint}")
    if not reasons:
        return None
    if not matched_evidence:
        matched_evidence.update(signals["evidence_ids"])
    priority = _prioritize(record, signals, environment)
    confidence = _match_confidence(record, signals, matched_evidence)
    next_step = record.safe_next_steps[0] if record.safe_next_steps else record.remediation_summary
    reason = "; ".join(sorted(set(reasons)))[:500]
    match_id = _stable_id("knowledge_match", record.record_id, sorted(matched_nodes), sorted(matched_evidence), reason)
    return KnowledgeMatch(
        match_id=match_id,
        knowledge_record_id=record.record_id,
        matched_node_ids=tuple(sorted(matched_nodes)),
        matched_evidence_ids=tuple(sorted(matched_evidence)),
        matched_technology=matched_technology,
        matched_surface=matched_surface,
        match_reason=reason,
        confidence=confidence,
        priority=priority,
        severity_hint=record.severity_hint,
        recommended_safe_next_step=next_step,
        requires_human_review=priority in {"high", "critical"} or record.record_type in {"cve", "kev"},
        tags=record.tags + (record.record_type, "knowledge-match"),
        metadata={
            "record_type": record.record_type,
            "confirmed_vulnerability": False,
            "source": "offline_fixture",
        },
    )


def _prioritize(record: SecurityKnowledgeRecord, signals: dict[str, Any], environment: str) -> str:
    priority = _priority(record.severity_hint)
    if record.record_type == "kev":
        priority = _bump(priority)
    if record.record_type == "epss" and float(_object(record.metadata).get("score", 0.0) or 0.0) >= 0.7:
        priority = _bump(priority)
    has_missing = bool(signals["missing_controls"])
    has_admin_or_auth = any(str(item.get("node_type")) in {"admin_surface", "auth_surface"} for item in signals["surfaces"])
    has_api_without_auth = any(str(item.get("node_type")) == "api_surface" for item in signals["surfaces"]) and "auth_indicators_present" not in signals["endpoint_hints"]
    if has_missing and has_admin_or_auth and priority not in {"high", "critical"} and any(tag in record.tags for tag in ("clickjacking", "secure-configuration", "admin-surface")):
        priority = _bump(priority)
    if has_api_without_auth and priority not in {"high", "critical"} and any(tag in record.tags for tag in ("api", "authorization-review")):
        priority = _bump(priority)
    if environment == "production" and priority in {"low", "medium"}:
        priority = _bump(priority)
    if _has_low_confidence_technology(signals) and priority in {"high", "critical"} and record.record_type not in {"kev", "epss"}:
        priority = "medium"
    return priority


def _match_confidence(record: SecurityKnowledgeRecord, signals: dict[str, Any], matched_evidence: set[str]) -> str:
    confidence = record.confidence
    if matched_evidence and confidence == "low":
        confidence = "medium"
    if _has_low_confidence_technology(signals) and confidence == "high":
        confidence = "medium"
    return confidence


def _has_low_confidence_technology(signals: dict[str, Any]) -> bool:
    return any(str(item.get("confidence", "medium")) == "low" for item in signals["technologies"])


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    if not value:
        return False
    return any(pattern and (pattern in value or value in pattern) for pattern in patterns)


def _priority(value: str) -> str:
    lowered = str(value or "info").lower()
    return lowered if lowered in PRIORITIES else "info"


def _bump(priority: str) -> str:
    index = PRIORITIES.index(_priority(priority))
    return PRIORITIES[min(index + 1, len(PRIORITIES) - 1)]


def _safe_tuple(values: Any) -> tuple[str, ...]:
    return tuple(sorted({_safe_text(item) for item in _list(values) if str(item).strip()}))


def _safe_optional(value: Any) -> str | None:
    if value is None:
        return None
    return _safe_text(value)


def _safe_text(value: Any) -> str:
    return str(redact_value(value or "")).strip()


def _norm(value: Any) -> str:
    return str(redact_value(value or "")).lower().replace("_", "-").strip()


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


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
