import io
import inspect
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget
from aegis_ev.recon_planner import plan_safe_recon
from aegis_ev.tool_adapters import (
    BUILTIN_TOOL_IDS,
    ToolCapability,
    ToolCapabilityRegistry,
    build_tool_audit_event,
    check_tool_availability,
    default_parser_contracts,
    default_tool_registry,
    evidence_from_parsed_tool_result,
    evidence_from_tool_availability,
    evidence_from_tool_plan,
    parse_tool_output,
    plan_tool_action,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "tools"
NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-tool-token-1234567890"


def auth(**kwargs):
    payload = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "environment": Environment.STAGING,
        "allowed_impact_levels": [ImpactLevel.GREEN],
        "request_budget": PolicyBudget(max_requests=10),
    }
    payload.update(kwargs)
    return AuthorizationProfile(**payload)


def auth_dict(**kwargs):
    payload = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "environment": "staging",
        "allowed_impact_levels": ["green"],
        "request_budget": {"max_requests": 10, "max_requests_per_minute": 30, "max_concurrency": 2},
    }
    payload.update(kwargs)
    return payload


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class GreenTierToolAdapterTests(unittest.TestCase):
    def test_default_green_tier_capabilities_registered(self):
        registry = default_tool_registry()
        tool_ids = {tool.tool_id for tool in registry.list_green_tools()}
        self.assertIn("builtin_safe_http_fetch", tool_ids)
        self.assertIn("local_semgrep_static_plan", tool_ids)
        self.assertTrue(all(registry.get(tool_id).tier == "green" for tool_id in tool_ids))

    def test_duplicate_tool_id_rejected(self):
        registry = ToolCapabilityRegistry()
        capability = default_tool_registry().get("builtin_safe_header_analysis")
        registry.register(capability)
        with self.assertRaises(ValueError):
            registry.register(capability)

    def test_unsupported_tier_rejected(self):
        with self.assertRaises(ValueError):
            ToolCapability(
                tool_id="bad_tool",
                display_name="Bad",
                description="Bad",
                category="bad",
                tier="blue",
                supported_actions=("bad",),
            )

    def test_list_green_tier_tools(self):
        tools = default_tool_registry().list_green_tools()
        self.assertGreaterEqual(len(tools), 5)
        self.assertEqual([tool.tool_id for tool in tools], sorted(tool.tool_id for tool in tools))

    def test_availability_uses_which_without_running_binary(self):
        calls = []

        def fake_which(binary):
            calls.append(binary)
            return "/usr/bin/semgrep"

        availability = check_tool_availability("local_semgrep_static_plan", which=fake_which)
        self.assertEqual(calls, ["semgrep"])
        self.assertTrue(availability.available)
        self.assertFalse(availability.safe_to_execute_now)

    def test_external_tools_remain_execution_disabled(self):
        for tool_id in {"local_semgrep_static_plan", "local_syft_sbom_plan", "local_grype_scan_plan", "local_trivy_config_plan"}:
            availability = check_tool_availability(tool_id, which=lambda _: "/usr/bin/tool")
            self.assertFalse(availability.safe_to_execute_now)
            self.assertEqual(availability.reason, "planning_only_external_tool")

    def test_dry_run_defaults_true_and_argv_preview_is_list(self):
        plan = plan_tool_action(
            {"tool_id": "builtin_safe_http_fetch", "action": "fetch_metadata", "target": "https://portfolio.example.test"},
            authorization_profile=auth(),
        )
        self.assertTrue(plan.dry_run)
        self.assertTrue(plan.allowed)
        self.assertIsInstance(plan.to_dict()["argv_preview"], list)
        self.assertNotIsInstance(plan.to_dict()["argv_preview"], str)

    def test_dangerous_shell_metacharacters_rejected(self):
        plan = plan_tool_action(
            {
                "tool_id": "builtin_safe_header_analysis",
                "action": "analyze_headers",
                "arguments": {"header_file": "headers.json; echo bad"},
            }
        )
        self.assertFalse(plan.allowed)
        self.assertIn("unsafe_argument_value:header_file", plan.errors)

    def test_user_supplied_executable_path_rejected(self):
        plan = plan_tool_action(
            {
                "tool_id": "local_semgrep_static_plan",
                "action": "plan_static_analysis",
                "arguments": {"executable": "/tmp/custom-semgrep"},
            },
            which=lambda _: "/usr/bin/semgrep",
        )
        self.assertFalse(plan.allowed)
        self.assertIn("forbidden_argument:executable", plan.errors)

    def test_unsupported_action_denied(self):
        plan = plan_tool_action({"tool_id": "builtin_safe_header_analysis", "action": "run_anything"})
        self.assertFalse(plan.allowed)
        self.assertIn("unsupported_action", plan.errors)

    def test_out_of_scope_target_denied_through_policy(self):
        plan = plan_tool_action(
            {"tool_id": "builtin_safe_http_fetch", "action": "fetch_metadata", "target": "https://outside.example.test"},
            authorization_profile=auth(),
        )
        self.assertFalse(plan.allowed)
        self.assertIn("target_out_of_scope", plan.errors)

    def test_secrets_redacted_from_arguments(self):
        plan = plan_tool_action(
            {
                "tool_id": "builtin_safe_header_analysis",
                "action": "analyze_headers",
                "arguments": {"token": SECRET_VALUE, "safe_name": "demo"},
            }
        )
        serialized = plan.serialize()
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("<redacted>", serialized)

    def test_no_raw_command_strings_or_shell_true_path_exists(self):
        import aegis_ev.tool_adapters as tool_adapters

        source = inspect.getsource(tool_adapters)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess", source)
        plan = plan_tool_action(
            {"tool_id": "builtin_safe_header_analysis", "action": "analyze_headers", "arguments": {"safe_name": "demo"}}
        )
        rendered = json.dumps(plan.to_dict())
        self.assertNotIn(" && ", rendered)
        self.assertNotIn("shell=True", rendered)

    def test_parser_contract_validation(self):
        contracts = default_parser_contracts()
        self.assertIn("semgrep_like_static_finding", contracts)
        self.assertEqual(contracts["syft_like_sbom"].tool_id, "local_syft_sbom_plan")

    def test_sample_semgrep_like_parser_creates_candidate_only(self):
        payload = json.loads((FIXTURES / "semgrep_sample_output.json").read_text(encoding="utf-8"))
        result = parse_tool_output("semgrep_like_static_finding", payload)
        self.assertEqual(result.item_count, 1)
        self.assertEqual(result.candidate_findings[0]["status"], "candidate")
        self.assertNotIn("confirmed", json.dumps(result.to_dict()).lower())

    def test_sample_syft_like_parser_creates_sbom_evidence_only(self):
        payload = json.loads((FIXTURES / "syft_sample_sbom.json").read_text(encoding="utf-8"))
        result = parse_tool_output("syft_like_sbom", payload)
        evidence = evidence_from_parsed_tool_result(result)
        self.assertEqual(result.item_count, 2)
        self.assertEqual(result.candidate_findings, ())
        self.assertEqual(evidence.source_type, EvidenceSourceType.TOOL_ADAPTER.value)

    def test_sample_grype_like_parser_creates_intel_evidence_not_confirmed_finding(self):
        payload = json.loads((FIXTURES / "grype_sample_vuln.json").read_text(encoding="utf-8"))
        result = parse_tool_output("grype_like_vulnerability", payload)
        self.assertEqual(result.item_count, 1)
        self.assertEqual(result.candidate_findings, ())
        self.assertNotIn("confirmed", json.dumps(result.to_dict()).lower())

    def test_evidence_generated_from_tool_plan_and_availability(self):
        availability = check_tool_availability("builtin_safe_header_analysis")
        plan = plan_tool_action({"tool_id": "builtin_safe_header_analysis", "action": "analyze_headers"})
        self.assertEqual(evidence_from_tool_availability(availability).source_type, EvidenceSourceType.TOOL_ADAPTER.value)
        self.assertEqual(evidence_from_tool_plan(plan).source_type, EvidenceSourceType.TOOL_ADAPTER.value)

    def test_audit_safe_event_generated_from_tool_plan(self):
        plan = plan_tool_action({"tool_id": "builtin_safe_header_analysis", "action": "analyze_headers"})
        event = build_tool_audit_event("tool_plan_created", tool_id=plan.tool_id, plan=plan, timestamp_utc="2026-01-01T00:00:00+00:00")
        self.assertEqual(event.event_type, "tool_plan_created")
        self.assertFalse(event.metadata["tool_execution"])

    def test_recon_planner_attaches_builtin_capability_references(self):
        plan = plan_safe_recon({"target": "https://portfolio.example.test"}, authorization_profile=auth())
        fetch = next(step for step in plan.steps if step.step_type == "safe_fetch_metadata")
        self.assertEqual(fetch.metadata["tool_capability_id"], "builtin_safe_http_fetch")

    def test_cli_list_tool_capabilities_returns_parseable_json(self):
        code, response = run_cli(["list-tool-capabilities"], {"tier": "green"})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertGreater(response["result"]["tool_count"], 0)

    def test_cli_check_tool_availability_returns_parseable_json(self):
        code, response = run_cli(["check-tool-availability"], {"tool_id": "builtin_safe_header_analysis"})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["availability"]["available"])

    def test_cli_plan_tool_action_returns_parseable_json(self):
        code, response = run_cli(
            ["plan-tool-action"],
            {
                "tool_id": "builtin_safe_http_fetch",
                "action": "fetch_metadata",
                "target": "https://portfolio.example.test",
                "authorization_profile": auth_dict(),
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["plan"]["dry_run"])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["plan-tool-action"], {"tool_id": "builtin_safe_header_analysis"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_no_real_external_tool_execution_network_api_keys_or_real_portfolio(self):
        import aegis_ev.tool_adapters as tool_adapters

        source = inspect.getsource(tool_adapters)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("alperenmanas", source.lower())
        for tool_id in BUILTIN_TOOL_IDS:
            self.assertNotIn(SECRET_VALUE, json.dumps(default_tool_registry().get(tool_id).to_dict(), sort_keys=True))

    def test_no_unsafe_fixture_language(self):
        rendered = ""
        for path in FIXTURES.glob("*.json"):
            rendered += path.read_text(encoding="utf-8").lower()
        self.assertNotIn("reverse shell", rendered)
        self.assertNotIn("shell payload", rendered)
        self.assertNotIn("dump credentials", rendered)


if __name__ == "__main__":
    unittest.main()
