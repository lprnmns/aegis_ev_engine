from __future__ import annotations

import ipaddress
import json
import hashlib
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .audit import canonical_json, redact_target, redact_value
from .models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from .policy import PolicyEngine


class ProjectStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class TargetType(str, Enum):
    WEB = "web"
    API = "api"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"
    MOBILE = "mobile"
    DESKTOP = "desktop"
    UNKNOWN = "unknown"


class SessionStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScopeDefinition:
    scope_id: str
    allowlist_domains: tuple[str, ...] = field(default_factory=tuple)
    allowlist_urls: tuple[str, ...] = field(default_factory=tuple)
    allowlist_cidrs: tuple[str, ...] = field(default_factory=tuple)
    denylist: tuple[str, ...] = field(default_factory=tuple)
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = field(default_factory=tuple)
    environment: Environment | str = Environment.STAGING
    valid_from: str | None = None
    valid_until: str | None = None
    owner_attestation: str | None = None
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        environment = _enum_value(Environment, self.environment, "environment")
        domains = tuple(sorted({_normalize_domain(domain) for domain in self.allowlist_domains if str(domain).strip()}))
        urls = tuple(sorted({_normalize_url(url) for url in self.allowlist_urls if str(url).strip()}))
        cidrs = tuple(sorted({_normalize_cidr(cidr) for cidr in self.allowlist_cidrs if str(cidr).strip()}))
        schemes = tuple(sorted({str(scheme).lower() for scheme in self.allowed_schemes if str(scheme).strip()}))
        if not schemes:
            raise ValueError("allowed_schemes must not be empty")
        for scheme in schemes:
            if scheme not in {"http", "https"}:
                raise ValueError(f"unsupported scheme: {scheme}")
        ports = tuple(sorted({int(port) for port in self.allowed_ports}))
        for port in ports:
            if port <= 0 or port > 65535:
                raise ValueError(f"invalid port: {port}")
        object.__setattr__(self, "allowlist_domains", domains)
        object.__setattr__(self, "allowlist_urls", urls)
        object.__setattr__(self, "allowlist_cidrs", cidrs)
        object.__setattr__(self, "denylist", tuple(sorted({redact_value(str(item)) for item in self.denylist})))
        object.__setattr__(self, "allowed_schemes", schemes)
        object.__setattr__(self, "allowed_ports", ports)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "owner_attestation", _safe_text(self.owner_attestation))
        object.__setattr__(self, "notes", _safe_text(self.notes))
        object.__setattr__(self, "tags", tuple(sorted({str(tag) for tag in self.tags})))
        if self.valid_from is not None:
            _parse_datetime(self.valid_from)
        if self.valid_until is not None:
            _parse_datetime(self.valid_until)
        if self.valid_from and self.valid_until and _parse_datetime(self.valid_from) >= _parse_datetime(self.valid_until):
            raise ValueError("valid_from must be before valid_until")

    def is_empty(self) -> bool:
        return not (self.allowlist_domains or self.allowlist_urls or self.allowlist_cidrs)

    def to_authorization_profile(
        self,
        *,
        owner: str,
        authorization_profile_id: str | None = None,
        now: datetime | None = None,
    ) -> AuthorizationProfile:
        if self.is_empty():
            raise ValueError("scope allowlist must not be empty")
        current = now or datetime.now(timezone.utc)
        valid_from = _parse_datetime(self.valid_from) if self.valid_from else current
        valid_until = _parse_datetime(self.valid_until) if self.valid_until else current.replace(year=current.year + 1)
        domains = set(self.allowlist_domains)
        for url in self.allowlist_urls:
            parsed = urlsplit(url)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
        return AuthorizationProfile(
            owner=owner or authorization_profile_id or self.scope_id,
            allowed_domains=sorted(domains),
            allowed_cidrs=list(self.allowlist_cidrs),
            valid_from=valid_from,
            valid_until=valid_until,
            environment=self.environment,
            allowed_impact_levels=[ImpactLevel.GREEN],
            request_budget=PolicyBudget(max_requests=1, max_requests_per_minute=30, max_concurrency=2),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "allowlist_domains": list(self.allowlist_domains),
            "allowlist_urls": list(self.allowlist_urls),
            "allowlist_cidrs": list(self.allowlist_cidrs),
            "denylist": list(self.denylist),
            "allowed_schemes": list(self.allowed_schemes),
            "allowed_ports": list(self.allowed_ports),
            "environment": self.environment,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "owner_attestation": self.owner_attestation,
            "notes": self.notes,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class TargetRecord:
    target_id: str
    target_type: TargetType | str
    value: str
    normalized_value: str = ""
    display_name: str | None = None
    environment: Environment | str = Environment.STAGING
    in_scope: bool = False
    scope_reason: str = "not_validated"
    authorization_profile_id: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at_utc: str = field(default_factory=utc_now)
    updated_at_utc: str | None = None

    def __post_init__(self) -> None:
        target_type = _enum_value(TargetType, self.target_type, "target_type")
        environment = _enum_value(Environment, self.environment, "environment")
        value = str(redact_value(self.value)).strip()
        if not value:
            raise ValueError("target value must not be empty")
        normalized = self.normalized_value or normalize_target_value(target_type, value)
        object.__setattr__(self, "target_type", target_type)
        object.__setattr__(self, "value", redact_target(value) if _is_url_type(target_type) else value)
        object.__setattr__(self, "normalized_value", normalized)
        object.__setattr__(self, "display_name", _safe_text(self.display_name))
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "tags", tuple(sorted({str(tag) for tag in self.tags})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))
        if self.updated_at_utc is None:
            object.__setattr__(self, "updated_at_utc", self.created_at_utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "display_name": self.display_name,
            "environment": self.environment,
            "in_scope": self.in_scope,
            "scope_reason": self.scope_reason,
            "authorization_profile_id": self.authorization_profile_id,
            "tags": list(self.tags),
            "metadata": redact_value(self.metadata),
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
        }


@dataclass(frozen=True)
class ProjectRecord:
    project_id: str
    name: str
    description: str | None = None
    customer_name: str | None = None
    environment: Environment | str = Environment.STAGING
    created_at_utc: str = field(default_factory=utc_now)
    updated_at_utc: str | None = None
    status: ProjectStatus | str = ProjectStatus.DRAFT
    authorization_profile_id: str | None = None
    scope: ScopeDefinition | None = None
    targets: tuple[TargetRecord, ...] = field(default_factory=tuple)
    imports: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    report_ids: tuple[str, ...] = field(default_factory=tuple)
    audit_log_path: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("project name must not be empty")
        status = _enum_value(ProjectStatus, self.status, "status")
        environment = _enum_value(Environment, self.environment, "environment")
        targets = tuple(sorted(self.targets, key=lambda target: target.target_id))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "description", _safe_text(self.description))
        object.__setattr__(self, "customer_name", _safe_text(self.customer_name))
        object.__setattr__(self, "targets", targets)
        object.__setattr__(self, "imports", _sorted_strings(self.imports))
        object.__setattr__(self, "evidence_ids", _sorted_strings(self.evidence_ids))
        object.__setattr__(self, "finding_ids", _sorted_strings(self.finding_ids))
        object.__setattr__(self, "report_ids", _sorted_strings(self.report_ids))
        object.__setattr__(self, "audit_log_path", redact_value(self.audit_log_path))
        object.__setattr__(self, "tags", _sorted_strings(self.tags))
        object.__setattr__(self, "metadata", redact_value(self.metadata))
        if self.updated_at_utc is None:
            object.__setattr__(self, "updated_at_utc", self.created_at_utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "customer_name": self.customer_name,
            "environment": self.environment,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "status": self.status,
            "authorization_profile_id": self.authorization_profile_id,
            "scope": self.scope.to_dict() if self.scope is not None else None,
            "targets": [target.to_dict() for target in self.targets],
            "imports": list(self.imports),
            "evidence_ids": list(self.evidence_ids),
            "finding_ids": list(self.finding_ids),
            "report_ids": list(self.report_ids),
            "audit_log_path": _safe_text(self.audit_log_path),
            "tags": list(self.tags),
            "metadata": redact_value(self.metadata),
        }


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    project_id: str
    created_at_utc: str = field(default_factory=utc_now)
    updated_at_utc: str | None = None
    actor: str = ""
    purpose: str = ""
    status: SessionStatus | str = SessionStatus.DRAFT
    selected_targets: tuple[str, ...] = field(default_factory=tuple)
    imported_source_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    approval_ids: tuple[str, ...] = field(default_factory=tuple)
    report_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        status = _enum_value(SessionStatus, self.status, "status")
        object.__setattr__(self, "actor", _safe_text(self.actor))
        object.__setattr__(self, "purpose", _safe_text(self.purpose))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "selected_targets", _sorted_strings(self.selected_targets))
        object.__setattr__(self, "imported_source_ids", _sorted_strings(self.imported_source_ids))
        object.__setattr__(self, "evidence_ids", _sorted_strings(self.evidence_ids))
        object.__setattr__(self, "finding_ids", _sorted_strings(self.finding_ids))
        object.__setattr__(self, "approval_ids", _sorted_strings(self.approval_ids))
        object.__setattr__(self, "report_ids", _sorted_strings(self.report_ids))
        object.__setattr__(self, "metadata", redact_value(self.metadata))
        if self.updated_at_utc is None:
            object.__setattr__(self, "updated_at_utc", self.created_at_utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "project_id": self.project_id,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "actor": self.actor,
            "purpose": self.purpose,
            "status": self.status,
            "selected_targets": list(self.selected_targets),
            "imported_source_ids": list(self.imported_source_ids),
            "evidence_ids": list(self.evidence_ids),
            "finding_ids": list(self.finding_ids),
            "approval_ids": list(self.approval_ids),
            "report_ids": list(self.report_ids),
            "metadata": redact_value(self.metadata),
        }


class ProjectWorkspaceStore:
    def __init__(self) -> None:
        self._projects: dict[str, ProjectRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}

    def create_project(self, project: ProjectRecord) -> ProjectRecord:
        if project.project_id in self._projects:
            raise ValueError(f"Duplicate project_id: {project.project_id}")
        self._projects[project.project_id] = project
        return project

    def get_project(self, project_id: str) -> ProjectRecord:
        try:
            return self._projects[project_id]
        except KeyError as exc:
            raise KeyError(f"Unknown project_id: {project_id}") from exc

    def list_projects(self) -> list[ProjectRecord]:
        return [self._projects[key] for key in sorted(self._projects)]

    def update_project_status(self, project_id: str, status: ProjectStatus | str, *, now: str | None = None) -> ProjectRecord:
        project = self.get_project(project_id)
        updated = replace(project, status=status, updated_at_utc=now or utc_now())
        self._projects[project_id] = updated
        return updated

    def add_target(self, project_id: str, target: TargetRecord) -> TargetRecord:
        project = self.get_project(project_id)
        for existing in project.targets:
            if existing.target_type == target.target_type and existing.normalized_value == target.normalized_value:
                return existing
            if existing.target_id == target.target_id:
                raise ValueError(f"Duplicate target_id: {target.target_id}")
        targets = tuple(sorted(project.targets + (target,), key=lambda item: item.target_id))
        self._projects[project_id] = replace(project, targets=targets, updated_at_utc=utc_now())
        return target

    def list_project_targets(self, project_id: str) -> list[TargetRecord]:
        return list(self.get_project(project_id).targets)

    def add_import_reference(self, project_id: str, import_id: str) -> ProjectRecord:
        return self._link_project_ref(project_id, "imports", import_id)

    def add_evidence_reference(self, project_id: str, evidence_id: str) -> ProjectRecord:
        return self._link_project_ref(project_id, "evidence_ids", evidence_id)

    def add_finding_reference(self, project_id: str, finding_id: str) -> ProjectRecord:
        return self._link_project_ref(project_id, "finding_ids", finding_id)

    def add_report_reference(self, project_id: str, report_id: str) -> ProjectRecord:
        return self._link_project_ref(project_id, "report_ids", report_id)

    def create_session(self, session: SessionRecord) -> SessionRecord:
        if session.session_id in self._sessions:
            raise ValueError(f"Duplicate session_id: {session.session_id}")
        self.get_project(session.project_id)
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> SessionRecord:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise KeyError(f"Unknown session_id: {session_id}") from exc

    def list_sessions(self, project_id: str | None = None) -> list[SessionRecord]:
        sessions = [self._sessions[key] for key in sorted(self._sessions)]
        if project_id is not None:
            sessions = [session for session in sessions if session.project_id == project_id]
        return sessions

    def update_session_status(self, session_id: str, status: SessionStatus | str, *, now: str | None = None) -> SessionRecord:
        session = self.get_session(session_id)
        updated = replace(session, status=status, updated_at_utc=now or utc_now())
        self._sessions[session_id] = updated
        return updated

    def _link_project_ref(self, project_id: str, field_name: str, value: str) -> ProjectRecord:
        project = self.get_project(project_id)
        current = tuple(getattr(project, field_name))
        updated_values = tuple(sorted(set(current + (str(value),))))
        updated = replace(project, **{field_name: updated_values, "updated_at_utc": utc_now()})
        self._projects[project_id] = updated
        return updated

    def to_dict(self) -> dict[str, Any]:
        return {
            "projects": [project.to_dict() for project in self.list_projects()],
            "sessions": [session.to_dict() for session in self.list_sessions()],
        }

    def export_json(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(canonical_json(self.to_dict()) + "\n", encoding="utf-8")

    @classmethod
    def import_json(cls, path: str | Path) -> ProjectWorkspaceStore:
        store = cls()
        input_path = Path(path)
        if not input_path.exists():
            return store
        payload = json.loads(input_path.read_text(encoding="utf-8") or "{}")
        for item in payload.get("projects", []):
            project = project_from_dict(item)
            store._projects[project.project_id] = project
        for item in payload.get("sessions", []):
            session = session_from_dict(item)
            store._sessions[session.session_id] = session
        return store


def project_from_dict(payload: dict[str, Any]) -> ProjectRecord:
    scope_payload = payload.get("scope")
    targets = tuple(target_from_dict(item) for item in payload.get("targets", []))
    scope = scope_from_dict(scope_payload) if isinstance(scope_payload, dict) else None
    return ProjectRecord(
        project_id=str(payload["project_id"]),
        name=str(payload["name"]),
        description=payload.get("description"),
        customer_name=payload.get("customer_name"),
        environment=payload.get("environment", Environment.STAGING.value),
        created_at_utc=payload.get("created_at_utc", utc_now()),
        updated_at_utc=payload.get("updated_at_utc"),
        status=payload.get("status", ProjectStatus.DRAFT.value),
        authorization_profile_id=payload.get("authorization_profile_id"),
        scope=scope,
        targets=targets,
        imports=tuple(payload.get("imports", [])),
        evidence_ids=tuple(payload.get("evidence_ids", [])),
        finding_ids=tuple(payload.get("finding_ids", [])),
        report_ids=tuple(payload.get("report_ids", [])),
        audit_log_path=payload.get("audit_log_path"),
        tags=tuple(payload.get("tags", [])),
        metadata=payload.get("metadata", {}),
    )


def target_from_dict(payload: dict[str, Any]) -> TargetRecord:
    return TargetRecord(
        target_id=str(payload["target_id"]),
        target_type=payload["target_type"],
        value=str(payload["value"]),
        normalized_value=str(payload.get("normalized_value", "")),
        display_name=payload.get("display_name"),
        environment=payload.get("environment", Environment.STAGING.value),
        in_scope=bool(payload.get("in_scope", False)),
        scope_reason=str(payload.get("scope_reason", "not_validated")),
        authorization_profile_id=payload.get("authorization_profile_id"),
        tags=tuple(payload.get("tags", [])),
        metadata=payload.get("metadata", {}),
        created_at_utc=payload.get("created_at_utc", utc_now()),
        updated_at_utc=payload.get("updated_at_utc"),
    )


def scope_from_dict(payload: dict[str, Any]) -> ScopeDefinition:
    return ScopeDefinition(
        scope_id=str(payload["scope_id"]),
        allowlist_domains=tuple(payload.get("allowlist_domains", [])),
        allowlist_urls=tuple(payload.get("allowlist_urls", [])),
        allowlist_cidrs=tuple(payload.get("allowlist_cidrs", [])),
        denylist=tuple(payload.get("denylist", [])),
        allowed_schemes=tuple(payload.get("allowed_schemes", ("https",))),
        allowed_ports=tuple(payload.get("allowed_ports", [])),
        environment=payload.get("environment", Environment.STAGING.value),
        valid_from=payload.get("valid_from"),
        valid_until=payload.get("valid_until"),
        owner_attestation=payload.get("owner_attestation"),
        notes=str(payload.get("notes", "")),
        tags=tuple(payload.get("tags", [])),
    )


def session_from_dict(payload: dict[str, Any]) -> SessionRecord:
    return SessionRecord(
        session_id=str(payload["session_id"]),
        project_id=str(payload["project_id"]),
        created_at_utc=payload.get("created_at_utc", utc_now()),
        updated_at_utc=payload.get("updated_at_utc"),
        actor=str(payload.get("actor", "")),
        purpose=str(payload.get("purpose", "")),
        status=payload.get("status", SessionStatus.DRAFT.value),
        selected_targets=tuple(payload.get("selected_targets", [])),
        imported_source_ids=tuple(payload.get("imported_source_ids", [])),
        evidence_ids=tuple(payload.get("evidence_ids", [])),
        finding_ids=tuple(payload.get("finding_ids", [])),
        approval_ids=tuple(payload.get("approval_ids", [])),
        report_ids=tuple(payload.get("report_ids", [])),
        metadata=payload.get("metadata", {}),
    )


def create_project_record(payload: dict[str, Any]) -> ProjectRecord:
    created = str(payload.get("created_at_utc") or utc_now())
    project_id = str(payload.get("project_id") or _stable_id("project", payload.get("name", ""), created))
    scope_payload = payload.get("scope")
    return ProjectRecord(
        project_id=project_id,
        name=str(payload["name"]),
        description=payload.get("description"),
        customer_name=payload.get("customer_name"),
        environment=payload.get("environment", Environment.STAGING.value),
        created_at_utc=created,
        updated_at_utc=payload.get("updated_at_utc"),
        status=payload.get("status", ProjectStatus.DRAFT.value),
        authorization_profile_id=payload.get("authorization_profile_id"),
        scope=scope_from_dict(scope_payload) if isinstance(scope_payload, dict) else None,
        audit_log_path=payload.get("audit_log_path"),
        tags=tuple(payload.get("tags", [])),
        metadata=payload.get("metadata", {}),
    )


def create_target_record(payload: dict[str, Any], project: ProjectRecord | None = None) -> TargetRecord:
    target_type = payload.get("target_type", TargetType.URL.value)
    value = str(payload.get("value", ""))
    normalized = normalize_target_value(str(target_type), value)
    target_id = str(payload.get("target_id") or _stable_id("target", str(target_type), normalized))
    in_scope = bool(payload.get("in_scope", False))
    scope_reason = str(payload.get("scope_reason", "not_validated"))
    metadata = dict(payload.get("metadata", {}))
    if project and project.scope:
        decision = validate_target_against_scope(value, str(target_type), project.scope, owner=project.customer_name or project.name)
        in_scope = decision["in_scope"]
        scope_reason = decision["scope_reason"]
        metadata["policy_decision"] = decision["policy_decision"]
    return TargetRecord(
        target_id=target_id,
        target_type=target_type,
        value=value,
        normalized_value=normalized,
        display_name=payload.get("display_name"),
        environment=payload.get("environment", project.environment if project else Environment.STAGING.value),
        in_scope=in_scope,
        scope_reason=scope_reason,
        authorization_profile_id=payload.get("authorization_profile_id") or (project.authorization_profile_id if project else None),
        tags=tuple(payload.get("tags", [])),
        metadata=metadata,
        created_at_utc=payload.get("created_at_utc", utc_now()),
        updated_at_utc=payload.get("updated_at_utc"),
    )


def create_session_record(payload: dict[str, Any]) -> SessionRecord:
    created = str(payload.get("created_at_utc") or utc_now())
    session_id = str(payload.get("session_id") or _stable_id("session", payload.get("project_id", ""), created))
    return SessionRecord(
        session_id=session_id,
        project_id=str(payload["project_id"]),
        created_at_utc=created,
        updated_at_utc=payload.get("updated_at_utc"),
        actor=str(payload.get("actor", "")),
        purpose=str(payload.get("purpose", "")),
        status=payload.get("status", SessionStatus.DRAFT.value),
        selected_targets=tuple(payload.get("selected_targets", [])),
        imported_source_ids=tuple(payload.get("imported_source_ids", [])),
        evidence_ids=tuple(payload.get("evidence_ids", [])),
        finding_ids=tuple(payload.get("finding_ids", [])),
        approval_ids=tuple(payload.get("approval_ids", [])),
        report_ids=tuple(payload.get("report_ids", [])),
        metadata=payload.get("metadata", {}),
    )


def validate_target_against_scope(
    value: str,
    target_type: TargetType | str,
    scope: ScopeDefinition,
    *,
    owner: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    normalized = normalize_target_value(str(target_type), value)
    if scope.is_empty():
        return {"in_scope": False, "scope_reason": "scope_allowlist_empty", "policy_decision": None}
    if _matches_denylist(normalized, scope.denylist):
        return {"in_scope": False, "scope_reason": "target_denylisted", "policy_decision": None}
    auth = scope.to_authorization_profile(owner=owner, now=now)
    target_for_policy = _policy_target(normalized, str(target_type))
    intent = ToolIntent(
        adapter="project_scope",
        target=target_for_policy,
        impact=ImpactLevel.GREEN,
        budget=RequestBudget(max_requests=1),
        action_type="validate_project_target",
    )
    decision = PolicyEngine().evaluate(intent, auth, now=now)
    if not decision.allowed:
        return {
            "in_scope": False,
            "scope_reason": decision.code,
            "policy_decision": decision.to_public_dict(),
        }
    if not _scheme_allowed(normalized, str(target_type), scope):
        return {
            "in_scope": False,
            "scope_reason": "scheme_not_allowed",
            "policy_decision": decision.to_public_dict(),
        }
    if not _port_allowed(normalized, str(target_type), scope):
        return {
            "in_scope": False,
            "scope_reason": "port_not_allowed",
            "policy_decision": decision.to_public_dict(),
        }
    return {"in_scope": True, "scope_reason": "allowed_by_project_scope", "policy_decision": decision.to_public_dict()}


def normalize_target_value(target_type: TargetType | str, value: str) -> str:
    target_type_value = _enum_value(TargetType, target_type, "target_type")
    raw = str(value).strip()
    if not raw:
        raise ValueError("target value must not be empty")
    if target_type_value in {TargetType.URL.value, TargetType.WEB.value, TargetType.API.value}:
        return _normalize_url(raw)
    if target_type_value == TargetType.DOMAIN.value:
        return _normalize_domain(raw)
    if target_type_value == TargetType.CIDR.value:
        return _normalize_cidr(raw)
    if target_type_value in {TargetType.MOBILE.value, TargetType.DESKTOP.value}:
        raise ValueError(f"{target_type_value} targets are modeled only; active modules are not implemented")
    return str(redact_value(raw))


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {parsed.scheme or '<missing>'}")
    if not parsed.hostname:
        raise ValueError("url target must include a host")
    host = parsed.hostname.lower()
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    path = "" if parsed.path in {"", "/"} else parsed.path
    return redact_target(urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))) or ""


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or " " in domain:
        raise ValueError(f"invalid domain target: {value}")
    return domain


def _normalize_cidr(value: str) -> str:
    return str(ipaddress.ip_network(value.strip(), strict=False))


def _policy_target(normalized: str, target_type: str) -> str:
    if target_type == TargetType.DOMAIN.value:
        return f"https://{normalized}"
    if target_type == TargetType.CIDR.value:
        return normalized
    return normalized


def _scheme_allowed(normalized: str, target_type: str, scope: ScopeDefinition) -> bool:
    if target_type in {TargetType.DOMAIN.value, TargetType.CIDR.value}:
        return True
    parsed = urlsplit(normalized)
    return parsed.scheme.lower() in scope.allowed_schemes


def _port_allowed(normalized: str, target_type: str, scope: ScopeDefinition) -> bool:
    if not scope.allowed_ports or target_type in {TargetType.DOMAIN.value, TargetType.CIDR.value}:
        return True
    parsed = urlsplit(normalized)
    return (parsed.port or (443 if parsed.scheme == "https" else 80)) in scope.allowed_ports


def _matches_denylist(normalized: str, denylist: tuple[str, ...]) -> bool:
    lowered = normalized.lower()
    return any(str(item).lower() in lowered for item in denylist)


def _is_url_type(target_type: str) -> bool:
    return target_type in {TargetType.URL.value, TargetType.WEB.value, TargetType.API.value}


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _enum_value(enum_cls: type[Enum], value: Any, field_name: str) -> str:
    try:
        return enum_cls(value).value
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value}") from exc


def _sorted_strings(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(sorted({str(value) for value in values}))


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()[:24]


def _safe_text(value: Any) -> Any:
    if value is None:
        return None
    redacted = str(redact_value(str(value)))
    return re.sub(r"[A-Za-z0-9][A-Za-z0-9_-]{19,}", "<redacted>", redacted)
