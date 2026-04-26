from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .models import PolicyDecision


GENESIS_HASH = "GENESIS"
REDACTED = "<redacted>"
SECRET_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "passwd",
    "pwd",
    "secret",
    "session",
    "set-cookie",
    "token",
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
TOKENISH_RE = re.compile(r"\b[A-Za-z0-9_-]{24,}\b")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp_utc: str
    actor: str
    event_type: str
    target: str | None
    normalized_target: str | None
    action: str
    impact_level: str | None
    decision_code: str | None
    allowed: bool | None
    required_approval: bool | None
    metadata: dict[str, Any]
    previous_hash: str
    event_hash: str

    @property
    def id(self) -> str:
        return self.event_id

    @property
    def timestamp(self) -> str:
        return self.timestamp_utc

    @property
    def details(self) -> dict[str, Any]:
        return self.metadata

    @property
    def hash(self) -> str:
        return self.event_hash


@dataclass(frozen=True)
class AuditVerificationResult:
    valid: bool
    event_count: int = 0
    last_hash: str = GENESIS_HASH
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid


class AuditLog:
    """Append-only JSONL audit log with a deterministic hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        actor: str,
        action: str,
        target: str | None,
        details: dict[str, Any] | None = None,
        *,
        event_type: str | None = None,
        normalized_target: str | None = None,
        impact_level: str | None = None,
        decision_code: str | None = None,
        allowed: bool | None = None,
        required_approval: bool | None = None,
        event_id: str | None = None,
        timestamp_utc: str | None = None,
    ) -> AuditEvent:
        previous_hash = self._last_hash()
        event = self.build_event(
            actor=actor,
            action=action,
            target=target,
            metadata=details or {},
            previous_hash=previous_hash,
            event_type=event_type or action,
            normalized_target=normalized_target,
            impact_level=impact_level,
            decision_code=decision_code,
            allowed=allowed,
            required_approval=required_approval,
            event_id=event_id,
            timestamp_utc=timestamp_utc,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(self.serialize_event(event) + "\n")
        return event

    def append_policy_decision(self, decision: PolicyDecision, actor: str = "system") -> AuditEvent:
        details = decision.to_audit_details()
        return self.append(
            actor=actor,
            action=f"policy.{decision.decision.value}",
            target=details.get("target"),
            details=details,
            event_type="policy_decision",
            normalized_target=details.get("normalized_target"),
            impact_level=details.get("impact_level"),
            decision_code=details.get("decision_code"),
            allowed=decision.allowed,
            required_approval=decision.required_approval,
        )

    def build_event(
        self,
        *,
        actor: str,
        action: str,
        target: str | None,
        metadata: dict[str, Any],
        previous_hash: str,
        event_type: str,
        normalized_target: str | None = None,
        impact_level: str | None = None,
        decision_code: str | None = None,
        allowed: bool | None = None,
        required_approval: bool | None = None,
        event_id: str | None = None,
        timestamp_utc: str | None = None,
    ) -> AuditEvent:
        base = {
            "event_id": event_id or f"audit_{uuid4().hex}",
            "timestamp_utc": timestamp_utc or datetime.now(timezone.utc).isoformat(),
            "actor": redact_value(actor),
            "event_type": redact_value(event_type),
            "target": redact_target(target),
            "normalized_target": redact_target(normalized_target),
            "action": redact_value(action),
            "impact_level": redact_value(impact_level),
            "decision_code": redact_value(decision_code),
            "allowed": allowed,
            "required_approval": required_approval,
            "metadata": redact_value(metadata),
            "previous_hash": previous_hash,
        }
        event_hash = self.compute_event_hash(base)
        return AuditEvent(event_hash=event_hash, **base)

    def verify(self) -> AuditVerificationResult:
        previous = GENESIS_HASH
        event_count = 0
        if not self.path.exists():
            return AuditVerificationResult(valid=True, event_count=0, last_hash=previous)

        for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                return AuditVerificationResult(
                    valid=False,
                    event_count=event_count,
                    last_hash=previous,
                    errors=[f"line {line_number}: empty audit record"],
                )
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                return AuditVerificationResult(
                    valid=False,
                    event_count=event_count,
                    last_hash=previous,
                    errors=[f"line {line_number}: malformed JSON: {exc.msg}"],
                )

            required = set(AuditEvent.__dataclass_fields__.keys())
            missing = sorted(required.difference(event))
            if missing:
                return AuditVerificationResult(
                    valid=False,
                    event_count=event_count,
                    last_hash=previous,
                    errors=[f"line {line_number}: missing fields: {', '.join(missing)}"],
                )

            actual_hash = event.get("event_hash")
            if event.get("previous_hash") != previous:
                return AuditVerificationResult(
                    valid=False,
                    event_count=event_count,
                    last_hash=previous,
                    errors=[f"line {line_number}: previous_hash does not match prior event"],
                )

            payload = dict(event)
            payload.pop("event_hash", None)
            expected_hash = self.compute_event_hash(payload)
            if expected_hash != actual_hash:
                return AuditVerificationResult(
                    valid=False,
                    event_count=event_count,
                    last_hash=previous,
                    errors=[f"line {line_number}: event_hash mismatch"],
                )

            previous = str(actual_hash)
            event_count += 1

        return AuditVerificationResult(valid=True, event_count=event_count, last_hash=previous)

    def _last_hash(self) -> str:
        result = self.verify()
        if not result.valid:
            raise ValueError(f"Cannot append to invalid audit log: {'; '.join(result.errors)}")
        return result.last_hash

    @staticmethod
    def serialize_event(event: AuditEvent) -> str:
        return canonical_json(asdict(event))

    @staticmethod
    def compute_event_hash(payload: dict[str, Any]) -> str:
        canonical = canonical_json(payload)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def redact_target(target: str | None) -> str | None:
    if target is None:
        return None
    try:
        parsed = urlsplit(str(target))
    except ValueError:
        return "<invalid-target>"
    if not parsed.scheme and not parsed.netloc:
        return redact_value(str(target))
    host = parsed.hostname or ""
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{host}:{port}"
    path = "/".join(_redact_string(segment) for segment in parsed.path.split("/"))
    return urlunsplit((parsed.scheme, netloc, path, "", ""))


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_secret_key(key_text):
                redacted[key_text] = REDACTED
            else:
                redacted[key_text] = redact_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.lower().replace("_", "-")
    return any(part in lowered for part in SECRET_KEY_PARTS)


def _redact_string(value: str) -> str:
    if not value:
        return value
    stripped = value.strip()
    if BEARER_RE.search(stripped):
        return BEARER_RE.sub("Bearer " + REDACTED, stripped)
    if _looks_tokenish(stripped):
        return REDACTED
    return value


def _looks_tokenish(value: str) -> bool:
    if len(value) < 24 or " " in value or "/" in value:
        return False
    return bool(TOKENISH_RE.fullmatch(value))
