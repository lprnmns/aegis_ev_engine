import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aegis_ev.ai_contracts import (
    build_ai_audit_event,
    build_planner_prompt_packet,
    build_reporter_prompt_packet,
    build_verifier_prompt_packet,
    default_ai_contracts,
    evidence_from_ai_validation,
    validate_ai_output_common,
    validate_planner_output,
    validate_reporter_output,
    validate_verifier_output,
)
from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "ai"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def context():
    return fixture("planner_context_packet.json")


def evidence_ids():
    return [item["evidence_id"] for item in context()["evidence"]]


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class AIContractsTests(unittest.TestCase):
    def test_default_ai_contracts_exist_for_core_roles(self):
        contracts = default_ai_contracts()
        self.assertIn("planner", contracts)
        self.assertIn("verifier", contracts)
        self.assertIn("reporter", contracts)
        self.assertFalse(contracts["planner"].metadata["model_invocation"])

    def test_prompt_packet_builder_redacts_secrets(self):
        payload = context()
        payload["metadata"]["api_key"] = "fake-secret-value"
        packet = build_planner_prompt_packet(payload)
        rendered = json.dumps(packet)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("fake-secret-value", rendered)

    def test_planner_packet_includes_allowed_and_forbidden_action_sets(self):
        packet = build_planner_prompt_packet(context())
        context_packet = packet["context_packet"]
        self.assertIn("safe_fetch_metadata", context_packet["allowed_action_set"])
        self.assertIn("raw_shell_execution", context_packet["forbidden_action_set"])

    def test_verifier_packet_includes_evidence_finding_distinction(self):
        packet = build_verifier_prompt_packet(context())
        context_packet = packet["context_packet"]
        self.assertEqual(context_packet["evidence_summary"]["count"], 2)
        self.assertEqual(context_packet["finding_summary"]["candidate_count"], 1)

    def test_reporter_packet_includes_limitations(self):
        packet = build_reporter_prompt_packet(context())
        self.assertIn("limitations", packet["expected_response_schema"])
        self.assertIn("no autonomous tool execution", " ".join(packet["prompt_template"]["safety_constraints"]))

    def test_valid_planner_output_passes_validation(self):
        result = validate_planner_output({"output": fixture("planner_output_valid.json"), "existing_evidence_ids": evidence_ids()})
        self.assertTrue(result.valid)

    def test_planner_output_with_forbidden_action_fails_validation(self):
        result = validate_planner_output({"output": fixture("planner_output_unsafe.json"), "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("external_scanner_execution", result.blocked_actions)

    def test_planner_output_with_amber_or_red_without_approval_fails_validation(self):
        output = fixture("planner_output_valid.json")
        output["recommended_steps"][0]["impact_level"] = "amber"
        output["recommended_steps"][0]["required_approval"] = False
        result = validate_planner_output({"output": output, "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("requires human approval", " ".join(result.errors))

    def test_planner_output_with_unknown_evidence_id_fails_validation(self):
        output = fixture("planner_output_valid.json")
        output["recommended_steps"][0]["related_evidence_ids"] = ["evidence_missing"]
        result = validate_planner_output({"output": output, "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("unknown evidence", " ".join(result.errors))

    def test_verifier_output_overclaiming_confirmed_vulnerability_fails_validation(self):
        result = validate_verifier_output({"output": fixture("verifier_output_overclaim.json"), "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("confirmed status requires", " ".join(result.errors))

    def test_verifier_output_inventing_evidence_fails_validation(self):
        output = fixture("verifier_output_valid.json")
        output["accepted_evidence_ids"] = ["evidence_unknown"]
        result = validate_verifier_output({"output": output, "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)

    def test_reporter_output_claiming_full_coverage_without_evidence_fails_validation(self):
        result = validate_reporter_output({"output": fixture("reporter_output_overclaim.json"), "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("overclaims", " ".join(result.errors))

    def test_reporter_output_containing_raw_secrets_fails_validation(self):
        output = fixture("reporter_output_valid.json")
        output["metadata"] = {"token": "fake-token-value"}
        result = validate_reporter_output({"output": output, "existing_evidence_ids": evidence_ids()})
        self.assertFalse(result.valid)
        self.assertIn("secret-like", " ".join(result.errors))

    def test_common_validator_catches_token_like_values(self):
        result = validate_ai_output_common({"role": "unknown", "value": "A" * 40}, role="unknown")
        self.assertFalse(result.valid)
        self.assertIn("secret-like", " ".join(result.errors))

    def test_common_validator_catches_forbidden_content(self):
        result = validate_ai_output_common({"role": "unknown", "note": "attempt a reverse shell"}, role="unknown")
        self.assertFalse(result.valid)
        self.assertIn("forbidden content", " ".join(result.errors))

    def test_evidence_generated_from_validation_result(self):
        validation = validate_planner_output({"output": fixture("planner_output_valid.json"), "existing_evidence_ids": evidence_ids()})
        evidence = evidence_from_ai_validation(validation)
        self.assertEqual(evidence.source_type, EvidenceSourceType.AI_CONTRACT_VALIDATION.value)

    def test_audit_safe_event_generated_for_validation_result(self):
        event = build_ai_audit_event(
            "ai_output_validation_passed",
            role="planner",
            target="https://portfolio.example.test",
            metadata={"validation_id": "validation_demo"},
            timestamp_utc="2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(event.event_type, "ai_output_validation_passed")
        self.assertFalse(event.metadata["model_invocation"])
        self.assertFalse(event.metadata["tool_execution"])

    def test_cli_build_ai_planner_packet_returns_parseable_json(self):
        code, response = run_cli(["build-ai-planner-packet"], context())
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("packet", response["result"])

    def test_cli_validate_ai_planner_output_returns_parseable_json(self):
        code, response = run_cli(
            ["validate-ai-planner-output"],
            {"output": fixture("planner_output_valid.json"), "existing_evidence_ids": evidence_ids()},
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["validation"]["valid"])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["validate-ai-planner-output"], {"output": fixture("planner_output_unsafe.json"), "existing_evidence_ids": evidence_ids()})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "ai_validation_failed")

    def test_no_model_calls_network_api_keys_or_real_portfolio_url(self):
        import inspect
        import aegis_ev.ai_contracts as ai_contracts

        source = inspect.getsource(ai_contracts)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("GEMINI_API_KEY", source)
        self.assertNotIn("alperenmanas", source.lower())


if __name__ == "__main__":
    unittest.main()
