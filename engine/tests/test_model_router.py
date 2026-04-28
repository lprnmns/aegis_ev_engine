import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main
from aegis_ev.model_router import (
    ModelProviderProfile,
    ModelRouter,
    MockModelProvider,
    build_model_request_envelope,
    build_model_router_audit_event,
    default_provider_profiles,
    default_routing_policy,
    evidence_from_model_routing,
    execute_mock_model_request,
    list_model_providers,
    route_model_request,
    validate_model_response_envelope,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "model_router"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def request_input():
    return fixture("planner_request_input.json")


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class ModelRouterTests(unittest.TestCase):
    def test_default_mock_provider_exists(self):
        providers = default_provider_profiles()
        self.assertIn("mock_safe_provider", providers)
        self.assertTrue(providers["mock_safe_provider"].enabled)
        self.assertTrue(providers["mock_safe_provider"].safe_for_local_tests)

    def test_account_cli_provider_can_be_represented_but_disabled(self):
        profile = default_provider_profiles()["future_account_cli_provider"]
        self.assertEqual(profile.provider_type, "account_cli")
        self.assertFalse(profile.enabled)
        self.assertTrue(profile.requires_account_auth)

    def test_api_provider_can_be_represented_but_disabled(self):
        profile = default_provider_profiles()["future_api_provider"]
        self.assertEqual(profile.provider_type, "api")
        self.assertFalse(profile.enabled)
        self.assertTrue(profile.requires_api_key)

    def test_no_provider_profile_contains_credentials(self):
        rendered = json.dumps([profile.to_dict() for profile in default_provider_profiles().values()]).lower()
        self.assertNotIn("openai_api_key", rendered)
        self.assertNotIn("gemini_api_key", rendered)
        self.assertNotIn("secret-value", rendered)

    def test_default_routing_policy_selects_mock_provider(self):
        provider = ModelRouter().select_provider("planner")
        self.assertEqual(provider.provider_id, "mock_safe_provider")

    def test_api_key_provider_denied_by_default(self):
        with self.assertRaises(ValueError):
            ModelRouter().select_provider("planner", provider_id="future_api_provider")

    def test_network_provider_denied_by_default(self):
        provider = ModelProviderProfile(
            provider_id="network_mock_disabled",
            display_name="Network Provider",
            provider_type="mock",
            auth_mode="mock",
            supported_roles=("planner",),
            supported_capabilities=("json_output",),
            requires_network=True,
            enabled=True,
            safe_for_local_tests=True,
        )
        router = ModelRouter(providers={**default_provider_profiles(), provider.provider_id: provider})
        with self.assertRaises(ValueError):
            router.select_provider("planner", provider_id=provider.provider_id)

    def test_account_auth_provider_denied_for_runtime_execution(self):
        with self.assertRaises(ValueError):
            ModelRouter().select_provider("planner", provider_id="future_account_cli_provider")

    def test_request_envelope_built_from_planner_prompt_packet(self):
        request = build_model_request_envelope(request_input())
        self.assertEqual(request.role, "planner")
        self.assertEqual(request.provider_id, "mock_safe_provider")
        self.assertIn("contract", request.prompt_packet)

    def test_request_envelope_redacts_secrets(self):
        payload = request_input()
        payload["metadata"]["token"] = "fake-token-value"
        request = build_model_request_envelope(payload)
        rendered = json.dumps(request.to_dict())
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("fake-token-value", rendered)

    def test_mock_planner_response_validates_successfully(self):
        response = execute_mock_model_request(request_input())
        self.assertEqual(response.validation_status, "passed")

    def test_unsafe_mock_planner_response_fails_validation(self):
        response = execute_mock_model_request({**request_input(), "fixture_key": "planner_unsafe"})
        self.assertEqual(response.validation_status, "failed")
        self.assertIn("external_scanner_execution", response.guardrail_actions)

    def test_verifier_mock_response_validates_successfully(self):
        response = execute_mock_model_request({**request_input(), "role": "verifier"})
        self.assertEqual(response.validation_status, "passed")

    def test_reporter_mock_response_validates_successfully(self):
        response = execute_mock_model_request({**request_input(), "role": "reporter"})
        self.assertEqual(response.validation_status, "passed")

    def test_live_provider_execution_denied(self):
        request = build_model_request_envelope(request_input()).to_dict()
        request["provider_id"] = "future_api_provider"
        with self.assertRaises(ValueError):
            execute_mock_model_request({"request_envelope": request})

    def test_response_envelope_does_not_store_chain_of_thought(self):
        response = execute_mock_model_request(request_input())
        rendered = json.dumps(response.to_dict()).lower()
        self.assertNotIn("chain of thought", rendered)
        self.assertIsNone(response.raw_response)

    def test_evidence_generated_from_routing_validation_result(self):
        response = execute_mock_model_request(request_input())
        evidence = evidence_from_model_routing(response)
        self.assertEqual(evidence.source_type, EvidenceSourceType.MODEL_ROUTER.value)

    def test_audit_events_generated_for_provider_selection_and_validation(self):
        event = build_model_router_audit_event(
            "model_provider_selected",
            provider_id="mock_safe_provider",
            role="planner",
            timestamp_utc="2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(event.event_type, "model_provider_selected")
        self.assertFalse(event.metadata["live_model_call"])

    def test_cli_list_model_providers_returns_parseable_json(self):
        code, response = run_cli(["list-model-providers"], {})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("providers", response["result"])

    def test_cli_build_model_request_envelope_returns_parseable_json(self):
        code, response = run_cli(["build-model-request-envelope"], request_input())
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("request_envelope", response["result"])

    def test_cli_execute_mock_model_request_returns_parseable_json(self):
        code, response = run_cli(["execute-mock-model-request"], request_input())
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["response_envelope"]["validation_status"], "passed")

    def test_cli_invalid_provider_returns_structured_error(self):
        code, response = run_cli(["route-model-request"], {**request_input(), "provider_id": "future_api_provider"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_validate_model_response_envelope_command_path(self):
        request = build_model_request_envelope(request_input()).to_dict()
        response = validate_model_response_envelope(
            {
                "request_envelope": request,
                "parsed_response": fixture("mock_planner_response_valid.json"),
            }
        )
        self.assertEqual(response.validation_status, "passed")

    def test_route_model_request_returns_mock_plan(self):
        result = route_model_request(request_input())
        self.assertEqual(result["provider"]["provider_id"], "mock_safe_provider")

    def test_list_model_providers_uses_fixture_shape(self):
        payload = fixture("provider_profiles.json") | fixture("routing_policy_mock_only.json")
        result = list_model_providers(payload)
        self.assertEqual(len(result["providers"]), 3)

    def test_no_model_calls_network_api_keys_or_real_portfolio_url(self):
        import inspect
        import aegis_ev.model_router as model_router

        source = inspect.getsource(model_router)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("GEMINI_API_KEY", source)
        self.assertNotIn("alperenmanas", source.lower())


if __name__ == "__main__":
    unittest.main()
