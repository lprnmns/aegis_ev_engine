import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_ev.adapters import AdapterPlanner, ToolActionRequest, default_registry
from aegis_ev.audit import AuditLog, REDACTED
from aegis_ev.evidence import (
    EvidenceRecord,
    EvidenceSourceType,
    EvidenceStore,
    EvidenceType,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
    VerificationState,
    candidate_finding_from_evidence,
    evidence_from_adapter_plan,
    evidence_from_audit_event,
    evidence_from_policy_decision,
)
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from aegis_ev.policy import PolicyEngine


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-evidence-token-1234567890"


def auth(**kwargs):
    base = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["example.com"],
        "allowed_cidrs": [],
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "environment": Environment.STAGING,
        "allowed_impact_levels": [ImpactLevel.GREEN, ImpactLevel.AMBER, ImpactLevel.RED],
        "request_budget": PolicyBudget(max_requests=10, max_requests_per_minute=30, max_concurrency=2),
    }
    base.update(kwargs)
    return AuthorizationProfile(**base)


def sample_evidence(**kwargs):
    base = {
        "evidence_id": "evidence_1",
        "created_at_utc": "2026-01-01T00:00:00+00:00",
        "evidence_type": EvidenceType.MANUAL_NOTE,
        "source_type": EvidenceSourceType.HUMAN,
        "source_id": "manual_1",
        "target": "https://example.com/path?token=" + SECRET_VALUE,
        "normalized_target": "https://example.com/path",
        "title": "Manual evidence",
        "summary": "Operator note",
        "redacted_raw": {"Authorization": "Bearer " + SECRET_VALUE},
        "structured_data": {"safe": True, "api_key": SECRET_VALUE},
        "tags": ("manual", "manual"),
        "confidence": FindingConfidence.MEDIUM,
    }
    base.update(kwargs)
    return EvidenceRecord(**base)


def sample_finding(**kwargs):
    base = {
        "finding_id": "finding_1",
        "created_at_utc": "2026-01-01T00:00:00+00:00",
        "title": "Candidate finding",
        "description": "Evidence-backed candidate",
        "severity": FindingSeverity.LOW,
        "confidence": FindingConfidence.MEDIUM,
        "evidence_ids": ("evidence_1",),
        "remediation": "Review configuration.",
        "verification_state": VerificationState.EVIDENCE_BACKED,
    }
    base.update(kwargs)
    return FindingRecord(**base)


class EvidenceStoreTests(unittest.TestCase):
    def test_evidence_hash_is_deterministic(self):
        first = sample_evidence()
        second = sample_evidence()
        self.assertEqual(first.hash, second.hash)

    def test_evidence_serialization_is_stable(self):
        record = sample_evidence(structured_data={"b": 2, "a": 1})
        serialized_once = record.serialize()
        serialized_twice = record.serialize()
        self.assertEqual(serialized_once, serialized_twice)
        self.assertLess(serialized_once.index('"a"'), serialized_once.index('"b"'))

    def test_evidence_redacts_secrets(self):
        record = sample_evidence()
        serialized = record.serialize()
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertNotIn("token=", serialized)
        self.assertIn(REDACTED, serialized)
        self.assertTrue(record.redaction_applied)

    def test_finding_defaults_to_candidate_not_confirmed(self):
        finding = FindingRecord(title="Potential issue", description="Needs review")
        self.assertEqual(finding.status, FindingStatus.CANDIDATE.value)
        self.assertEqual(finding.verification_state, VerificationState.UNVERIFIED.value)
        self.assertNotEqual(finding.status, FindingStatus.CONFIRMED.value)

    def test_finding_cannot_be_verified_without_evidence(self):
        with self.assertRaises(ValueError):
            FindingRecord(
                title="Unsupported finding",
                description="No evidence",
                verification_state=VerificationState.VERIFIED,
            )

    def test_evidence_can_link_to_finding(self):
        store = EvidenceStore()
        store.add_evidence(sample_evidence())
        store.add_finding(
            sample_finding(
                finding_id="finding_2",
                evidence_ids=(),
                verification_state=VerificationState.UNVERIFIED,
            )
        )
        updated = store.link_evidence_to_finding("evidence_1", "finding_2")
        self.assertEqual(updated.evidence_ids, ("evidence_1",))

    def test_missing_evidence_link_denied(self):
        store = EvidenceStore()
        store.add_finding(
            sample_finding(
                finding_id="finding_2",
                evidence_ids=(),
                verification_state=VerificationState.UNVERIFIED,
            )
        )
        with self.assertRaises(KeyError):
            store.link_evidence_to_finding("missing", "finding_2")

    def test_store_add_get_list_behavior(self):
        store = EvidenceStore()
        evidence = store.add_evidence(sample_evidence())
        finding = store.add_finding(sample_finding())
        self.assertEqual(store.get_evidence(evidence.evidence_id), evidence)
        self.assertEqual(store.get_finding(finding.finding_id), finding)
        self.assertEqual([item.evidence_id for item in store.list_evidence()], ["evidence_1"])
        self.assertEqual([item.finding_id for item in store.list_findings()], ["finding_1"])

    def test_duplicate_evidence_id_denied(self):
        store = EvidenceStore()
        store.add_evidence(sample_evidence())
        with self.assertRaises(ValueError):
            store.add_evidence(sample_evidence())

    def test_duplicate_finding_id_denied(self):
        store = EvidenceStore()
        store.add_evidence(sample_evidence())
        store.add_finding(sample_finding())
        with self.assertRaises(ValueError):
            store.add_finding(sample_finding())

    def test_jsonl_export_import_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.jsonl"
            store = EvidenceStore()
            store.add_evidence(sample_evidence())
            store.add_finding(sample_finding())
            store.export_jsonl(path)
            imported = EvidenceStore.import_jsonl(path)
            self.assertEqual(imported.get_evidence("evidence_1").hash, store.get_evidence("evidence_1").hash)
            self.assertEqual(imported.get_finding("finding_1").evidence_ids, ("evidence_1",))

    def test_json_export_import_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            store = EvidenceStore()
            store.add_evidence(sample_evidence())
            store.add_finding(sample_finding())
            store.export_json(path)
            imported = EvidenceStore.import_json(path)
            self.assertEqual(imported.get_evidence("evidence_1").hash, store.get_evidence("evidence_1").hash)

    def test_policy_decision_evidence_creation(self):
        intent = ToolIntent(
            adapter="safe_headers",
            target="https://user:pass@example.com/path?token=" + SECRET_VALUE,
            impact=ImpactLevel.GREEN,
            budget=RequestBudget(max_requests=1),
        )
        decision = PolicyEngine().evaluate(intent, auth(), now=NOW)
        evidence = evidence_from_policy_decision(decision, source_id="policy_1")
        serialized = evidence.serialize()
        self.assertEqual(evidence.evidence_type, EvidenceType.POLICY_DECISION.value)
        self.assertTrue(evidence.structured_data["allowed"])
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertNotIn("user:pass", serialized)

    def test_audit_event_evidence_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            event = log.append(
                "system",
                "policy.deny",
                "https://example.com/path?token=" + SECRET_VALUE,
                {"Authorization": "Bearer " + SECRET_VALUE},
            )
            evidence = evidence_from_audit_event(event)
            serialized = evidence.serialize()
            self.assertEqual(evidence.related_audit_event_id, event.event_id)
            self.assertNotIn(SECRET_VALUE, serialized)
            self.assertIn(REDACTED, serialized)

    def test_adapter_plan_evidence_creation(self):
        request = ToolActionRequest(
            action_id="action_1",
            adapter_id="echo_plan",
            target="https://example.com",
            action="plan",
            arguments={"message": "safe"},
            requested_impact_level=ImpactLevel.GREEN,
            actor="tester",
            authorization_profile=auth(),
        )
        plan = AdapterPlanner(default_registry()).plan(request)
        evidence = evidence_from_adapter_plan(plan, source_id="plan_1")
        self.assertEqual(evidence.evidence_type, EvidenceType.ADAPTER_PLAN.value)
        self.assertEqual(evidence.related_adapter_id, "echo_plan")
        self.assertTrue(evidence.structured_data["allowed"])

    def test_no_raw_secrets_in_serialized_evidence_or_finding(self):
        evidence = sample_evidence()
        finding = sample_finding(target="https://example.com?token=" + SECRET_VALUE)
        serialized = json.dumps({"evidence": evidence.to_dict(), "finding": finding.to_dict()}, sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertNotIn("token=", serialized)

    def test_invalid_severity_denied(self):
        with self.assertRaises(ValueError):
            FindingRecord(title="Bad", description="Bad", severity="urgent")

    def test_invalid_status_denied(self):
        with self.assertRaises(ValueError):
            FindingRecord(title="Bad", description="Bad", status="complete")

    def test_conservative_verification_defaults(self):
        evidence = sample_evidence()
        high = candidate_finding_from_evidence(
            evidence,
            title="Critical candidate",
            description="Still not auto-confirmed",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
        )
        low = candidate_finding_from_evidence(
            evidence,
            title="Low confidence draft",
            description="Needs human review",
            confidence=FindingConfidence.LOW,
        )
        self.assertEqual(high.status, FindingStatus.CANDIDATE.value)
        self.assertEqual(high.verification_state, VerificationState.EVIDENCE_BACKED.value)
        self.assertEqual(low.status, FindingStatus.DRAFT.value)
        self.assertEqual(low.verification_state, VerificationState.HUMAN_REVIEW_REQUIRED.value)

    def test_no_network_side_effects(self):
        store = EvidenceStore()
        store.add_evidence(sample_evidence(target="https://example.com"))
        self.assertEqual(len(store.list_evidence()), 1)


if __name__ == "__main__":
    unittest.main()
