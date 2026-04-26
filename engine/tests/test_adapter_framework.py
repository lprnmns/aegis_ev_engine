import inspect
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_ev.adapters import (
    AdapterPlanner,
    AdapterRegistry,
    DuplicateAdapterError,
    EchoPlanAdapter,
    ToolActionRequest,
    UnknownAdapterError,
    WebHeaderConfigCheckAdapter,
    default_registry,
)
from aegis_ev.audit import AuditLog, REDACTED
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-adapter-token-1234567890"


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
        "require_approval_for_amber": True,
    }
    base.update(kwargs)
    return AuthorizationProfile(**base)


def request(**kwargs):
    base = {
        "action_id": "action_123",
        "adapter_id": "echo_plan",
        "target": "https://example.com",
        "action": "plan",
        "arguments": {"message": "safe hello"},
        "requested_impact_level": ImpactLevel.GREEN,
        "actor": "tester",
        "authorization_profile": auth(),
    }
    base.update(kwargs)
    return ToolActionRequest(**base)


class AdapterFrameworkTests(unittest.TestCase):
    def test_adapter_registration(self):
        registry = AdapterRegistry()
        registry.register(EchoPlanAdapter())
        self.assertEqual(registry.get("echo_plan").metadata.display_name, "Echo Plan Adapter")

    def test_duplicate_adapter_rejection(self):
        registry = AdapterRegistry()
        registry.register(EchoPlanAdapter())
        with self.assertRaises(DuplicateAdapterError):
            registry.register(EchoPlanAdapter())

    def test_unknown_adapter_rejection(self):
        with self.assertRaises(UnknownAdapterError):
            default_registry().get("missing")

    def test_valid_safe_adapter_plan_allowed(self):
        plan = AdapterPlanner(default_registry()).plan(request())
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.policy_decision.code, "allowed")
        self.assertEqual(plan.adapter_id, "echo_plan")
        self.assertEqual(plan.action, "plan")
        self.assertEqual(plan.normalized_target, "https://example.com")
        self.assertEqual(plan.command_preview, ["aegis-ev-adapter", "echo_plan", "plan", "--dry-run"])
        self.assertTrue(plan.dry_run)

    def test_out_of_scope_target_denied(self):
        plan = AdapterPlanner(default_registry()).plan(request(target="https://evil.test"))
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.decision_code, "target_out_of_scope")
        self.assertEqual(plan.command_preview, [])

    def test_unsupported_action_denied(self):
        plan = AdapterPlanner(default_registry()).plan(request(action="scan"))
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.decision_code, "unsupported_action")
        self.assertIn("Unsupported action", plan.denial_reason)

    def test_invalid_argument_denied(self):
        plan = AdapterPlanner(default_registry()).plan(request(arguments={"message": 42}))
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.decision_code, "invalid_arguments")
        self.assertIn("must be a string", plan.denial_reason)

    def test_secret_argument_redaction(self):
        plan = AdapterPlanner(default_registry()).plan(
            request(arguments={"message": SECRET_VALUE, "api_token": SECRET_VALUE})
        )
        self.assertFalse(plan.allowed)
        serialized = json.dumps(plan.sanitized_arguments, sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn(REDACTED, serialized)

    def test_red_impact_requires_approval(self):
        plan = AdapterPlanner(default_registry()).plan(request(requested_impact_level=ImpactLevel.RED))
        self.assertFalse(plan.allowed)
        self.assertTrue(plan.required_approval)
        self.assertEqual(plan.policy_decision.code, "red_requires_approval")

    def test_budget_exceeded_denied(self):
        plan = AdapterPlanner(default_registry()).plan(request(requests_used=10))
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.policy_decision.code, "budget_exceeded")

    def test_production_amber_follows_policy(self):
        profile = auth(
            environment=Environment.PRODUCTION,
            require_approval_for_amber=False,
            require_approval_for_production_amber=True,
        )
        plan = AdapterPlanner(default_registry()).plan(
            request(requested_impact_level=ImpactLevel.AMBER, authorization_profile=profile)
        )
        self.assertFalse(plan.allowed)
        self.assertTrue(plan.required_approval)
        self.assertEqual(plan.policy_decision.code, "production_amber_requires_approval")

    def test_unknown_impact_denied(self):
        plan = AdapterPlanner(default_registry()).plan(request(requested_impact_level="purple"))
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.policy_decision.code, "unknown_impact")

    def test_dry_run_default_behavior(self):
        tool_request = request()
        self.assertTrue(tool_request.dry_run)
        plan = AdapterPlanner(default_registry()).plan(tool_request)
        self.assertTrue(plan.dry_run)
        self.assertIn("--dry-run", plan.command_preview)

    def test_no_shell_true_usage_in_framework(self):
        source = inspect.getsource(__import__("aegis_ev.adapters.framework", fromlist=[""]))
        self.assertNotIn("shell=True", source)
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.run", source)

    def test_audit_event_generated_for_allowed_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            plan = AdapterPlanner(default_registry()).plan(request(), audit_log=log)
            self.assertTrue(plan.allowed)
            self.assertIsNotNone(plan.audit_event_id)
            self.assertTrue(log.verify())
            raw = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertIn("adapter_plan", raw)
            self.assertIn("echo_plan", raw)

    def test_audit_safe_event_generated_for_denied_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            log = AuditLog(log_path)
            plan = AdapterPlanner(default_registry()).plan(
                request(target="https://evil.test/path?token=" + SECRET_VALUE), audit_log=log
            )
            self.assertFalse(plan.allowed)
            self.assertIsNotNone(plan.audit_event_id)
            raw = log_path.read_text(encoding="utf-8")
            self.assertNotIn(SECRET_VALUE, raw)
            self.assertIn("target_out_of_scope", raw)
            self.assertTrue(log.verify())

    def test_output_preview_contains_no_raw_secrets(self):
        plan = AdapterPlanner(default_registry()).plan(request(arguments={"message": SECRET_VALUE}))
        serialized = json.dumps(
            {
                "command_preview": plan.command_preview,
                "execution_preview": plan.execution_preview,
                "sanitized_arguments": plan.sanitized_arguments,
            },
            sort_keys=True,
        )
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn(REDACTED, serialized)

    def test_registry_list_behavior(self):
        adapters = default_registry().list_adapters()
        self.assertEqual([adapter.adapter_id for adapter in adapters], ["echo_plan", "web_header_config_check"])

    def test_no_network_side_effects(self):
        plan = AdapterPlanner(default_registry()).plan(request())
        self.assertTrue(plan.allowed)
        self.assertFalse(default_registry().get("echo_plan").metadata.requires_network)
        self.assertEqual(plan.estimated_budget["max_requests"], 1)

    def test_web_header_adapter_registered_and_safe(self):
        adapter = default_registry().get("web_header_config_check")
        self.assertIsInstance(adapter, WebHeaderConfigCheckAdapter)
        self.assertFalse(adapter.metadata.requires_network)
        self.assertTrue(adapter.metadata.safe_mode_supported)

    def test_web_header_adapter_rejects_invalid_arguments(self):
        plan = AdapterPlanner(default_registry()).plan(
            request(
                adapter_id="web_header_config_check",
                action="analyze_headers",
                arguments={"headers": "not-an-object"},
            )
        )
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.decision_code, "invalid_arguments")

    def test_web_header_adapter_allows_valid_arguments(self):
        plan = AdapterPlanner(default_registry()).plan(
            request(
                adapter_id="web_header_config_check",
                action="analyze_headers",
                arguments={"headers": {"server": "nginx"}},
            )
        )
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.adapter_id, "web_header_config_check")
        self.assertEqual(plan.execution_preview, "Analyze supplied HTTP headers and configuration locally without network access.")


if __name__ == "__main__":
    unittest.main()
