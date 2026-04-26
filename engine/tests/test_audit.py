import json
import tempfile
import unittest
from pathlib import Path

from aegis_ev.audit import AuditLog, REDACTED, redact_value
from aegis_ev.models import (
    AuthorizationProfile,
    Environment,
    ImpactLevel,
    PolicyBudget,
    RequestBudget,
    ToolIntent,
)
from aegis_ev.policy import PolicyEngine


SENSITIVE_SAMPLE = "not-a-real-token-value-1234567890"


class AuditLogTests(unittest.TestCase):
    def test_event_hash_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            event_one = log.build_event(
                actor="system",
                event_type="policy_decision",
                action="policy.allow",
                target="https://example.com/path?token=ignored",
                normalized_target="https://example.com/path",
                impact_level="green",
                decision_code="allowed",
                allowed=True,
                required_approval=False,
                metadata={"reason": "Allowed by policy"},
                previous_hash="GENESIS",
                event_id="audit_fixed",
                timestamp_utc="2026-01-01T00:00:00+00:00",
            )
            event_two = log.build_event(
                actor="system",
                event_type="policy_decision",
                action="policy.allow",
                target="https://example.com/path?token=ignored",
                normalized_target="https://example.com/path",
                impact_level="green",
                decision_code="allowed",
                allowed=True,
                required_approval=False,
                metadata={"reason": "Allowed by policy"},
                previous_hash="GENESIS",
                event_id="audit_fixed",
                timestamp_utc="2026-01-01T00:00:00+00:00",
            )
            self.assertEqual(event_one.event_hash, event_two.event_hash)

    def test_audit_log_hash_chain_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            log.append("system", "policy.allow", "https://example.com", {"reason": "test"})
            log.append("adapter", "adapter.completed", "https://example.com", {"count": 1})
            result = log.verify()
            self.assertTrue(result)
            self.assertEqual(result.event_count, 2)

    def test_audit_log_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append("system", "policy.allow", "https://example.com", {"reason": "test"})
            event = json.loads(path.read_text().splitlines()[0])
            event["metadata"]["reason"] = "tampered"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            result = log.verify()
            self.assertFalse(result)
            self.assertIn("event_hash mismatch", result.errors[0])

    def test_missing_middle_event_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append("system", "one", "https://example.com", {"order": 1})
            log.append("system", "two", "https://example.com", {"order": 2})
            log.append("system", "three", "https://example.com", {"order": 3})
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
            result = log.verify()
            self.assertFalse(result)
            self.assertIn("previous_hash", result.errors[0])

    def test_reordered_event_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append("system", "one", "https://example.com", {"order": 1})
            log.append("system", "two", "https://example.com", {"order": 2})
            log.append("system", "three", "https://example.com", {"order": 3})
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n", encoding="utf-8")
            result = log.verify()
            self.assertFalse(result)
            self.assertIn("previous_hash", result.errors[0])

    def test_append_creates_multiple_chained_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            first = log.append("system", "policy.deny", "https://example.com", {"reason": "test"})
            second = log.append("adapter", "adapter.skipped", "https://example.com", {"count": 0})
            self.assertEqual(second.previous_hash, first.event_hash)
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)

    def test_secret_values_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append(
                "system",
                "policy.deny",
                "https://user:pass@example.com/path/" + SENSITIVE_SAMPLE + "?api_key=ignored",
                {
                    "Authorization": "Bearer " + SENSITIVE_SAMPLE,
                    "Cookie": "sessionid=" + SENSITIVE_SAMPLE,
                    "nested": {"password": SENSITIVE_SAMPLE, "note": "safe"},
                },
            )
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(SENSITIVE_SAMPLE, raw)
            self.assertNotIn("api_key", raw)
            self.assertNotIn("user:pass", raw)
            self.assertIn(REDACTED, raw)

    def test_policy_decision_audit_event_does_not_include_raw_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = AuthorizationProfile(
                owner="customer-a/project-web",
                allowed_domains=["example.com"],
                valid_from=None,
                valid_until=None,
                environment=Environment.STAGING,
                allowed_impact_levels=[ImpactLevel.GREEN],
                request_budget=PolicyBudget(max_requests=5),
            )
            intent = ToolIntent(
                adapter="safe_headers",
                target=f"https://user:pass@example.com/path?token={SENSITIVE_SAMPLE}",
                impact=ImpactLevel.GREEN,
                budget=RequestBudget(max_requests=1),
            )
            decision = PolicyEngine().evaluate(intent, profile)
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append_policy_decision(decision)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(SENSITIVE_SAMPLE, raw)
            self.assertNotIn("user:pass", raw)
            self.assertNotIn("token=", raw)
            self.assertTrue(log.verify())

    def test_audit_serialization_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            event = log.build_event(
                actor="system",
                event_type="policy_decision",
                action="policy.deny",
                target="https://example.com",
                normalized_target="https://example.com",
                impact_level="green",
                decision_code="target_out_of_scope",
                allowed=False,
                required_approval=False,
                metadata={"b": 2, "a": 1},
                previous_hash="GENESIS",
                event_id="audit_fixed",
                timestamp_utc="2026-01-01T00:00:00+00:00",
            )
            serialized_once = log.serialize_event(event)
            serialized_twice = log.serialize_event(event)
            self.assertEqual(serialized_once, serialized_twice)
            self.assertLess(serialized_once.index('"a"'), serialized_once.index('"b"'))

    def test_malformed_audit_file_fails_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text("{not-json}\n", encoding="utf-8")
            result = AuditLog(path).verify()
            self.assertFalse(result)
            self.assertIn("malformed JSON", result.errors[0])

    def test_empty_audit_log_is_valid_with_zero_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text("", encoding="utf-8")
            result = AuditLog(path).verify()
            self.assertTrue(result)
            self.assertEqual(result.event_count, 0)

    def test_redaction_helper_has_no_network_side_effects(self):
        value = redact_value({"Authorization": "Bearer " + SENSITIVE_SAMPLE, "note": "safe"})
        self.assertEqual(value["Authorization"], REDACTED)
        self.assertEqual(value["note"], "safe")


if __name__ == "__main__":
    unittest.main()
