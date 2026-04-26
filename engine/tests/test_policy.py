import json
import unittest
from datetime import datetime, timedelta, timezone

from aegis_ev.models import (
    AuthorizationProfile,
    Environment,
    ImpactLevel,
    PolicyBudget,
    PolicyDecisionType,
    RequestBudget,
    ToolIntent,
)
from aegis_ev.policy import PolicyEngine


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


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


def intent(
    target="https://example.com",
    impact=ImpactLevel.GREEN,
    budget=None,
    requires_authentication=False,
    **kwargs,
):
    return ToolIntent(
        adapter="safe_headers",
        target=target,
        impact=impact,
        budget=budget or RequestBudget(max_requests=1),
        requires_authentication=requires_authentication,
        **kwargs,
    )


class PolicyEngineTests(unittest.TestCase):
    def evaluate(self, tool_intent=None, profile=None):
        return PolicyEngine().evaluate(tool_intent or intent(), profile or auth(), now=NOW)

    def test_valid_scoped_domain_allowed(self):
        decision = self.evaluate()
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_target, "https://example.com")
        self.assertEqual(decision.code, "allowed")

    def test_allows_supported_subdomain(self):
        decision = self.evaluate(intent("https://App.Example.Com./health?token=secret"))
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)
        self.assertEqual(decision.normalized_target, "https://app.example.com/health")

    def test_denies_out_of_scope_domain(self):
        decision = self.evaluate(intent("https://evil.test"))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "target_out_of_scope")
        self.assertIn("outside", decision.reason)

    def test_denies_lookalike_domain(self):
        decision = self.evaluate(intent("https://example.com.evil.test"))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "lookalike_domain")

    def test_denies_unsupported_scheme(self):
        decision = self.evaluate(intent("file:///etc/passwd"))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "unsupported_scheme")

    def test_expired_authorization_denied(self):
        expired = auth(valid_until=NOW - timedelta(seconds=1))
        decision = self.evaluate(profile=expired)
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "authorization_expired")

    def test_not_yet_valid_authorization_denied(self):
        future = auth(valid_from=NOW + timedelta(minutes=1), valid_until=NOW + timedelta(days=1))
        decision = self.evaluate(profile=future)
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "authorization_not_yet_valid")

    def test_empty_scope_denied(self):
        decision = self.evaluate(profile=auth(allowed_domains=[], allowed_cidrs=[]))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "empty_scope")

    def test_cidr_scoped_ip_allowed(self):
        profile = auth(allowed_domains=[], allowed_cidrs=["192.0.2.0/24"])
        decision = self.evaluate(intent("https://192.0.2.10/status"), profile)
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_red_action_requires_approval(self):
        decision = self.evaluate(intent(impact=ImpactLevel.RED))
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)
        self.assertTrue(decision.required_approval)
        self.assertEqual(decision.code, "red_requires_approval")
        self.assertFalse(decision.allowed)

    def test_red_action_with_explicit_approval_allowed(self):
        decision = self.evaluate(intent(impact=ImpactLevel.RED, approval_id="approval_123", approval_granted=True))
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)
        details = decision.to_audit_details()
        self.assertEqual(details["approval_id"], "approval_123")

    def test_unknown_impact_denied(self):
        decision = self.evaluate(intent(impact="purple"))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "unknown_impact")

    def test_impact_not_allowed_denied(self):
        profile = auth(allowed_impact_levels=[ImpactLevel.GREEN])
        decision = self.evaluate(intent(impact=ImpactLevel.AMBER), profile)
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "impact_not_allowed")

    def test_budget_exceeded_denied(self):
        decision = self.evaluate(intent(requests_used=10))
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertEqual(decision.code, "budget_exceeded")

    def test_budget_escalation_requires_approval(self):
        decision = self.evaluate(intent(budget=RequestBudget(max_requests=11)))
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)
        self.assertEqual(decision.code, "budget_escalation")

    def test_production_amber_approval_behavior(self):
        profile = auth(
            environment=Environment.PRODUCTION,
            require_approval_for_amber=False,
            require_approval_for_production_amber=True,
        )
        decision = self.evaluate(intent(impact=ImpactLevel.AMBER), profile)
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)
        self.assertEqual(decision.code, "production_amber_requires_approval")

    def test_authenticated_action_requires_approval(self):
        decision = self.evaluate(intent(requires_authentication=True))
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)
        self.assertEqual(decision.code, "authenticated_requires_approval")

    def test_audit_safe_decision_serialization(self):
        decision = self.evaluate(intent("https://user:pass@example.com/path?token=secret#frag"))
        details = decision.to_audit_details()
        serialized = json.dumps(details, sort_keys=True)
        self.assertEqual(details["target"], "https://example.com/path")
        self.assertEqual(details["normalized_target"], "https://example.com/path")
        self.assertIn("decision_code", details)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("pass@", serialized)
        self.assertNotIn("token", serialized)

    def test_public_decision_output_contains_no_secret_material(self):
        decision = self.evaluate(intent("https://example.com/path?api_key=topsecret"))
        public = json.dumps(decision.to_public_dict(), sort_keys=True)
        self.assertNotIn("topsecret", public)
        self.assertNotIn("api_key", public)


if __name__ == "__main__":
    unittest.main()
