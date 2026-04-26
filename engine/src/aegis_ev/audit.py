from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class AuditEvent:
    id: str
    timestamp: str
    actor: str
    action: str
    target: str | None
    details: dict[str, Any]
    previous_hash: str
    hash: str


class AuditLog:
    """Append-only JSONL audit log with a simple hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, actor: str, action: str, target: str | None, details: dict[str, Any] | None = None) -> AuditEvent:
        previous_hash = self._last_hash()
        base = {
            "id": f"audit_{uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        event_hash = self._hash_payload(base)
        event = AuditEvent(hash=event_hash, **base)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), sort_keys=True) + "\n")
        return event

    def verify(self) -> bool:
        previous = "GENESIS"
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            actual_hash = event.pop("hash")
            if event["previous_hash"] != previous:
                return False
            if self._hash_payload(event) != actual_hash:
                return False
            previous = actual_hash
        return True

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1])["hash"]

    @staticmethod
    def _hash_payload(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
