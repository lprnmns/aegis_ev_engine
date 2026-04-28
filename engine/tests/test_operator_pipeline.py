import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from aegis_ev.evidence import FindingStatus, VerificationState
from aegis_ev.http_fetch import SafeHttpTransportResponse
from aegis_ev.operator_pipeline import run_portfolio_operator_pipeline, run_portfolio_operator_pipeline_from_payload
from aegis_ev.portfolio_demo import PortfolioDemoInput


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_INPUT = ROOT / "fixtures" / "demo" / "portfolio_operator_input.example.json"
FETCH_FIXTURE = ROOT / "fixtures" / "demo" / "demo_operator_pipeline_fetch_result.json"
SECRET_VALUE = "not-a-real-operator-token-1234567890"


class CountingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, timeout_seconds):
        self.calls.append((method, url, timeout_seconds))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def payload(**overrides):
    data = json.loads(EXAMPLE_INPUT.read_text(encoding="utf-8"))
    data.update({"output_dir": None, "write_outputs": False, "include_report_contents": True, "now": "2026-01-01T00:00:00+00:00"})
    data.update(overrides)
    return data


def good_transport():
    fixture = json.loads(FETCH_FIXTURE.read_text(encoding="utf-8"))
    fixture["headers"]["Set-Cookie"] = "sid=" + SECRET_VALUE
    return CountingTransport([SafeHttpTransportResponse(**fixture)])


def run_pipeline(**overrides):
    transport = good_transport()
    result = run_portfolio_operator_pipeline(PortfolioDemoInput.from_payload(payload(**overrides)), transport=transport)
    return result, transport


class PortfolioOperatorPipelineTests(unittest.TestCase):
    def test_pipeline_denies_missing_owner_authorization_before_network(self):
        transport = good_transport()
        with self.assertRaises(ValueError):
            run_portfolio_operator_pipeline(PortfolioDemoInput.from_payload(payload(owner_authorization_attestation=False)), transport=transport)
        self.assertEqual(transport.calls, [])

    def test_pipeline_denies_safe_mode_false_before_network(self):
        transport = good_transport()
        with self.assertRaises(ValueError):
            run_portfolio_operator_pipeline(PortfolioDemoInput.from_payload(payload(safe_mode=False)), transport=transport)
        self.assertEqual(transport.calls, [])

    def test_pipeline_denies_out_of_scope_target_before_network(self):
        transport = good_transport()
        with self.assertRaises(ValueError):
            run_portfolio_operator_pipeline(PortfolioDemoInput.from_payload(payload(target_url="https://outside.example.test")), transport=transport)
        self.assertEqual(transport.calls, [])

    def test_valid_placeholder_input_with_fake_transport_completes(self):
        result, transport = run_pipeline()
        self.assertEqual(result.pipeline_id, "authorized_portfolio_operator_pipeline_v1")
        self.assertEqual(result.fetch_summary["status_code"], 200)
        self.assertEqual(transport.calls, [("HEAD", "https://portfolio.example.test", 5)])
        self.assertFalse(result.live_request_performed)

    def test_fake_fetch_result_feeds_header_checks(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.header_check_summary["check_count"], 0)
        self.assertIn("Missing Content-Security-Policy", result.reports["markdown"])

    def test_fingerprint_summary_is_produced(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.fingerprint_summary["detected_technology_count"], 0)

    def test_attack_surface_graph_summary_is_produced(self):
        result, _transport = run_pipeline()
        self.assertIn("Attack Surface Summary", result.reports["markdown"])
        self.assertGreater(result.attack_surface_summary["control_count"], 0)

    def test_vulnerability_intelligence_summary_is_produced(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.vulnerability_intel_summary["match_count"], 0)

    def test_safe_recon_plan_summary_is_produced(self):
        result, _transport = run_pipeline()
        self.assertIn("Safe Recon Plan", result.reports["markdown"])
        self.assertGreaterEqual(result.recon_plan_summary["step_count"], 1)

    def test_green_tier_capability_suggestions_are_attached(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.tool_capability_summary["suggestion_count"], 0)
        self.assertTrue(result.tool_capability_summary["dry_run_only"])
        self.assertFalse(result.tool_capability_summary["external_tool_execution"])

    def test_evidence_count_is_greater_than_zero(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.evidence_count, 0)

    def test_candidate_findings_are_produced_where_header_checks_support_them(self):
        result, _transport = run_pipeline()
        self.assertGreater(result.finding_count, 0)

    def test_no_findings_are_confirmed_by_default(self):
        result, _transport = run_pipeline()
        report = json.loads(result.reports["json"])
        statuses = {finding["status"] for finding in report["findings"]}
        verification_states = {finding["verification_state"] for finding in report["findings"]}
        self.assertNotIn(FindingStatus.CONFIRMED.value, statuses)
        self.assertNotIn(VerificationState.VERIFIED.value, verification_states)

    def test_markdown_report_generated(self):
        result, _transport = run_pipeline()
        self.assertIn("# Aegis EV Portfolio Operator Pipeline Security Validation Report", result.reports["markdown"])

    def test_json_report_generated(self):
        result, _transport = run_pipeline()
        report = json.loads(result.reports["json"])
        self.assertEqual(report["report_id"], "report_authorized_portfolio_operator_pipeline")
        self.assertIn("operator_pipeline_sections", report)

    def test_report_contains_integrated_sections(self):
        markdown = run_pipeline()[0].reports["markdown"]
        self.assertIn("Technology Fingerprint Summary", markdown)
        self.assertIn("Attack Surface Summary", markdown)
        self.assertIn("Vulnerability Intelligence Summary", markdown)
        self.assertIn("Safe Recon Plan", markdown)
        self.assertIn("Green-Tier Tool Capability Suggestions", markdown)

    def test_report_contains_no_unsafe_instructions_or_raw_secrets(self):
        result, _transport = run_pipeline()
        serialized = json.dumps(result.to_dict(), sort_keys=True).lower()
        self.assertNotIn(SECRET_VALUE.lower(), serialized)
        self.assertNotIn("reverse shell", serialized)
        self.assertNotIn("shell payload", serialized)
        self.assertNotIn("dump credentials", serialized)

    def test_audit_verification_passes(self):
        result, _transport = run_pipeline()
        self.assertTrue(result.audit_verification_status["valid"])
        self.assertGreaterEqual(result.audit_verification_status["event_count"], 10)

    def test_output_dir_writing_works_with_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _transport = run_pipeline(output_dir=tmp, write_outputs=True, include_report_contents=False)
            self.assertTrue(Path(result.report_paths["markdown"]).exists())
            self.assertTrue(Path(result.report_paths["json"]).exists())
            self.assertEqual(result.reports, {})
            json.loads(Path(result.report_paths["json"]).read_text(encoding="utf-8"))

    def test_cli_run_portfolio_operator_pipeline_returns_parseable_json(self):
        fixture = json.loads(FETCH_FIXTURE.read_text(encoding="utf-8"))
        fixture["headers"]["Set-Cookie"] = "sid=" + SECRET_VALUE
        data = payload(transport_fixture={"responses": [fixture]})
        completed = subprocess.run(
            [sys.executable, "-m", "aegis_ev.main", "run-portfolio-operator-pipeline"],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        response = json.loads(completed.stdout)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["pipeline"]["fetch_summary"]["status_code"], 200)
        self.assertNotIn(SECRET_VALUE, completed.stdout)

    def test_cli_invalid_input_returns_structured_error(self):
        completed = subprocess.run(
            [sys.executable, "-m", "aegis_ev.main", "run-portfolio-operator-pipeline"],
            input=json.dumps(payload(owner_authorization_attestation=False)),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        response = json.loads(completed.stdout)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_tests_perform_no_real_network_calls(self):
        import aegis_ev.operator_pipeline as operator_pipeline

        source = inspect.getsource(operator_pipeline)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)

    def test_no_api_keys_required_or_real_portfolio_hardcoded(self):
        result, _transport = run_pipeline()
        serialized = json.dumps(result.to_dict(), sort_keys=True).lower()
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("alperenmanas", serialized)


if __name__ == "__main__":
    unittest.main()
