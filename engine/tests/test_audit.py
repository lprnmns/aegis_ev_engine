import json
import tempfile
import unittest
from pathlib import Path

from aegis_ev.audit import AuditLog


class AuditLogTests(unittest.TestCase):
    def test_audit_log_hash_chain_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            log.append("system", "policy.allow", "https://example.com", {"reason": "test"})
            log.append("adapter", "adapter.completed", "https://example.com", {"count": 1})
            self.assertTrue(log.verify())

    def test_audit_log_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append("system", "policy.allow", "https://example.com", {"reason": "test"})
            event = json.loads(path.read_text().splitlines()[0])
            event["details"]["reason"] = "tampered"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            self.assertFalse(log.verify())


if __name__ == "__main__":
    unittest.main()
