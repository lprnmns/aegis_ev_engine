import unittest
from datetime import datetime, timedelta, timezone

from aegis_ev.models import AuthorizationProfile, ImpactLevel, RequestBudget, ToolIntent
from aegis_ev.policy import PolicyEngine
from aegis_ev.models import PolicyDecisionType


def auth(**kwargs):
    base = {"owner": "tester", "allowed_domains": ["example.com"]}
    base.update(kwargs)
    return AuthorizationProfile(**base)


def intent(target="https://example.com", impact=ImpactLevel.GREEN, budget=None, requires_authentication=False):
    return ToolIntent(
        adapter="safe_headers",
        target=target,
        impact=impact,
        budget=budget or RequestBudget(max_requests=1),
        requires_authentication=requires_authentication,
    )


class PolicyEngineTests(unittest.TestCase):
    def test_allows_exact_domain(self):
        decision = PolicyEngine().evaluate(intent(), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_allows_subdomain(self):
        decision = PolicyEngine().evaluate(intent("https://app.example.com"), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_denies_out_of_scope_domain(self):
        decision = PolicyEngine().evaluate(intent("https://evil.test"), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertIn("outside allowed domains", decision.reason)

    def test_denies_unsupported_scheme(self):
        decision = PolicyEngine().evaluate(intent("file:///etc/passwd"), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)

    def test_expired_authorization_denied(self):
        expired = auth(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
        decision = PolicyEngine().evaluate(intent(), expired)
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)

    def test_amber_requires_approval(self):
        decision = PolicyEngine().evaluate(intent(impact=ImpactLevel.AMBER), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)

    def test_red_requires_approval(self):
        decision = PolicyEngine().evaluate(intent(impact=ImpactLevel.RED), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)

    def test_authenticated_requires_approval(self):
        decision = PolicyEngine().evaluate(intent(requires_authentication=True), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)

    def test_safe_mode_large_budget_requires_approval(self):
        decision = PolicyEngine().evaluate(intent(budget=RequestBudget(max_requests=11)), auth())
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRES_APPROVAL)


if __name__ == "__main__":
    unittest.main()
