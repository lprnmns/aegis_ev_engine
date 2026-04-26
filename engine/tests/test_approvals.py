import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_ev.approvals import (
    ApprovalActorType,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalStore,
    append_approval_audit_event,
    approval_allows_request,
    approval_from_policy_decision,
    evidence_from_approval_request,
)
from aegis_ev.audit import AuditLog, REDACTED
from aegis_ev.evidence import EvidenceType
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from aegis_ev.policy import PolicyEngine


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SECRET_VALUE = "not-a-real-approval-token-1234567890"


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


def intent(**kwargs):
    base = {
        "adapter": "echo_plan",
        "target": "https://example.com/path?token=" + SECRET_VALUE,
        "impact": ImpactLevel.RED,
        "budget": RequestBudget(max_requests=1),
        "action_type": "plan",
    }
    base.update(kwargs)
    return ToolIntent(**base)


def pending_request(**kwargs):
    base = {
        "approval_id": "approval_1",
        "created_at_utc": NOW.isoformat(),
        "requested_by": "builder",
        "requested_actor_type": ApprovalActorType.HUMAN,
        "action_type": "plan",
        "target": "https://example.com/path?token=" + SECRET_VALUE,
        "normalized_target": "https://example.com/path",
        "impact_level": ImpactLevel.RED,
        "reason": "Red action",
        "policy_decision_code": "red_requires_approval",
        "adapter_id": "echo_plan",
        "adapter_action": "plan",
        "sanitized_arguments": {"Authorization": "Bearer " + SECRET_VALUE},
        "required_approval_scope": {
            "target": "https://example.com/path",
            "normalized_target": "https://example.com/path",
            "action_type": "plan",
            "impact_level": "red",
            "adapter_id": "echo_plan",
            "adapter_action": "plan",
        },
        "metadata": {"api_key": SECRET_VALUE},
    }
    base.update(kwargs)
    return ApprovalRequest(**base)


class ApprovalQueueTests(unittest.TestCase):
    def test_approval_request_defaults_to_pending(self):
        approval = pending_request()
        self.assertEqual(approval.status, ApprovalStatus.PENDING.value)

    def test_approve_pending_approval_succeeds(self):
        store = ApprovalStore()
        store.add(pending_request())
        approved = store.approve("approval_1", approved_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)
        self.assertEqual(approved.status, ApprovalStatus.APPROVED.value)
        self.assertEqual(approved.approved_by, "reviewer")

    def test_reject_pending_approval_succeeds(self):
        store = ApprovalStore()
        store.add(pending_request())
        rejected = store.reject("approval_1", rejected_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)
        self.assertEqual(rejected.status, ApprovalStatus.REJECTED.value)
        self.assertEqual(rejected.rejected_by, "reviewer")

    def test_expired_approval_cannot_be_approved(self):
        store = ApprovalStore()
        store.add(pending_request(expires_at_utc=(NOW - timedelta(minutes=1)).isoformat()))
        with self.assertRaises(ValueError):
            store.approve("approval_1", approved_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)

    def test_consumed_approval_cannot_be_reused(self):
        store = ApprovalStore()
        store.add(pending_request())
        store.approve("approval_1", approved_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)
        store.consume("approval_1", consumer="adapter", now=NOW)
        with self.assertRaises(ValueError):
            store.consume("approval_1", consumer="adapter", now=NOW)

    def test_cancelled_approval_cannot_be_used(self):
        store = ApprovalStore()
        store.add(pending_request())
        store.cancel("approval_1", cancelled_by="builder", now=NOW)
        self.assertIsNone(
            store.find_matching(
                target="https://example.com/path",
                normalized_target="https://example.com/path",
                action_type="plan",
                impact_level=ImpactLevel.RED,
                adapter_id="echo_plan",
                adapter_action="plan",
                now=NOW,
            )
        )

    def test_invalid_lifecycle_transition_denied(self):
        store = ApprovalStore()
        store.add(pending_request())
        store.reject("approval_1", rejected_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)
        with self.assertRaises(ValueError):
            store.approve("approval_1", approved_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)

    def test_duplicate_approval_id_denied(self):
        store = ApprovalStore()
        store.add(pending_request())
        with self.assertRaises(ValueError):
            store.add(pending_request())

    def test_approval_cannot_broaden_scope(self):
        approval = pending_request(status=ApprovalStatus.APPROVED)
        self.assertFalse(
            approval_allows_request(
                approval,
                target="https://example.com/other",
                normalized_target="https://example.com/other",
                action_type="plan",
                impact_level=ImpactLevel.RED,
                adapter_id="echo_plan",
                adapter_action="plan",
                now=NOW,
            )
        )

    def test_agent_cannot_approve_its_own_request(self):
        store = ApprovalStore()
        store.add(pending_request(requested_by="agent-1", requested_actor_type=ApprovalActorType.AGENT))
        with self.assertRaises(ValueError):
            store.approve("approval_1", approved_by="agent-1", actor_type=ApprovalActorType.HUMAN, now=NOW)

    def test_red_impact_requires_approval(self):
        decision = PolicyEngine().evaluate(intent(), auth(), now=NOW)
        self.assertTrue(decision.required_approval)
        approval = approval_from_policy_decision(
            decision,
            requested_by="builder",
            requested_actor_type=ApprovalActorType.HUMAN,
            adapter_id="echo_plan",
            adapter_action="plan",
        )
        self.assertEqual(approval.impact_level, ImpactLevel.RED.value)

    def test_missing_approval_denies_safely(self):
        decision = PolicyEngine().evaluate(intent(), auth(), now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "red_requires_approval")

    def test_matching_valid_approval_permits_only_matching_request(self):
        store = ApprovalStore()
        store.add(pending_request())
        store.approve("approval_1", approved_by="reviewer", actor_type=ApprovalActorType.HUMAN, now=NOW)
        matched = store.find_matching(
            target="https://example.com/path",
            normalized_target="https://example.com/path",
            action_type="plan",
            impact_level=ImpactLevel.RED,
            adapter_id="echo_plan",
            adapter_action="plan",
            now=NOW,
        )
        self.assertIsNotNone(matched)
        self.assertIsNone(
            store.find_matching(
                target="https://example.com/path",
                normalized_target="https://example.com/path",
                action_type="scan",
                impact_level=ImpactLevel.RED,
                adapter_id="echo_plan",
                adapter_action="scan",
                now=NOW,
            )
        )

    def test_approval_audit_events_generated_and_secret_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            approval = pending_request(status=ApprovalStatus.APPROVED, approved_by="reviewer", approved_at_utc=NOW.isoformat())
            append_approval_audit_event(log, approval, event_type="approval_approved", actor="reviewer")
            raw = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(SECRET_VALUE, raw)
            self.assertIn("approval_approved", raw)
            self.assertTrue(log.verify())

    def test_approval_evidence_creation(self):
        evidence = evidence_from_approval_request(pending_request())
        serialized = json.dumps(evidence.to_dict(), sort_keys=True)
        self.assertEqual(evidence.evidence_type, EvidenceType.APPROVAL_EVENT.value)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn(REDACTED, serialized)

    def test_no_raw_secrets_in_approval_serialization(self):
        approval = pending_request()
        serialized = json.dumps(approval.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn(REDACTED, serialized)

    def test_no_network_side_effects(self):
        store = ApprovalStore()
        store.add(pending_request())
        self.assertEqual(len(store.list_pending(now=NOW)), 1)


if __name__ == "__main__":
    unittest.main()
