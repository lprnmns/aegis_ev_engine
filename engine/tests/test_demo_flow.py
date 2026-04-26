import inspect
import json
import tempfile
import unittest
from pathlib import Path

from aegis_ev.demo_flow import PLACEHOLDER_TARGET, run_demo_flow


SECRET_VALUES = (
    "not-a-real-demo-token-1234567890",
    "not-a-real-demo-session-1234567890",
)


class DemoFlowTests(unittest.TestCase):
    def test_demo_flow_completes_successfully(self):
        result = run_demo_flow()
        self.assertEqual(result.demo_id, "demo_local_portfolio_placeholder_v1")
        self.assertFalse(result.errors)
        self.assertEqual(result.project_id, "project_demo_portfolio_placeholder")

    def test_demo_flow_returns_no_network_true(self):
        self.assertTrue(run_demo_flow().no_network)

    def test_demo_creates_project_target_scope_session_state(self):
        result = run_demo_flow()
        self.assertEqual(result.target_count, 2)
        self.assertEqual(result.project["scope"]["scope_id"], "scope_demo_portfolio_placeholder")
        self.assertEqual(result.session["status"], "completed")
        self.assertIn("target_demo_portfolio_placeholder", result.session["selected_targets"])

    def test_demo_imports_openapi_endpoints(self):
        result = run_demo_flow()
        self.assertGreaterEqual(result.imported_endpoint_count, 2)
        self.assertTrue(result.project["imports"])

    def test_demo_analyzes_supplied_headers(self):
        result = run_demo_flow()
        markdown = result.reports["markdown"]
        self.assertIn("Missing Content-Security-Policy", markdown)
        self.assertIn("Potentially unsafe CORS", markdown)

    def test_demo_creates_evidence(self):
        result = run_demo_flow()
        self.assertGreater(result.evidence_count, 0)
        self.assertTrue(result.evidence_ids)

    def test_demo_creates_candidate_findings(self):
        result = run_demo_flow()
        self.assertGreater(result.finding_count, 0)
        self.assertTrue(result.finding_ids)

    def test_demo_findings_are_not_confirmed_by_default(self):
        result = run_demo_flow()
        report = json.loads(result.reports["json"])
        statuses = {finding["status"] for finding in report["findings"]}
        verification_states = {finding["verification_state"] for finding in report["findings"]}
        self.assertNotIn("confirmed", statuses)
        self.assertNotIn("verified", verification_states)

    def test_demo_generates_markdown_report(self):
        markdown = run_demo_flow().reports["markdown"]
        self.assertIn("# Aegis EV Local Demo Project Security Validation Report", markdown)
        self.assertIn("Demo mode", markdown)

    def test_demo_generates_json_report(self):
        report = json.loads(run_demo_flow().reports["json"])
        self.assertEqual(report["schema_version"], "report.v1")
        self.assertEqual(report["report_id"], "report_demo_local_flow")

    def test_demo_reports_are_parseable_and_deterministic(self):
        first = run_demo_flow()
        second = run_demo_flow()
        self.assertEqual(first.reports["json"], second.reports["json"])
        self.assertEqual(first.reports["markdown"], second.reports["markdown"])
        json.loads(first.reports["json"])

    def test_demo_report_contains_demo_mode_disclaimer(self):
        markdown = run_demo_flow().reports["markdown"]
        self.assertIn("Demo/fixture mode only", markdown)
        self.assertIn("No live validation was performed", markdown)
        self.assertIn("not confirmed exploitability", markdown.lower())

    def test_demo_report_does_not_contain_raw_secrets(self):
        serialized = json.dumps(run_demo_flow().to_dict(), sort_keys=True)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, serialized)
        self.assertIn("redacted", serialized)

    def test_demo_audit_verification_passes(self):
        result = run_demo_flow()
        self.assertTrue(result.audit_verification_status["valid"])
        self.assertGreaterEqual(result.audit_verification_status["event_count"], 5)

    def test_generated_output_can_be_written_to_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_demo_flow(output_dir=tmp, write_outputs=True, include_report_contents=False)
            markdown_path = Path(result.report_paths["markdown"])
            json_path = Path(result.report_paths["json"])
            self.assertTrue(markdown_path.exists())
            self.assertTrue(json_path.exists())
            self.assertEqual(result.reports, {})
            json.loads(json_path.read_text(encoding="utf-8"))

    def test_no_network_side_effects(self):
        import aegis_ev.demo_flow as demo_flow

        source = inspect.getsource(demo_flow)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)

    def test_no_api_keys_required(self):
        result = run_demo_flow()
        self.assertTrue(result.no_network)
        self.assertNotIn("api_key", json.dumps(result.to_dict(), sort_keys=True).lower())

    def test_no_real_portfolio_url_hardcoded(self):
        self.assertEqual(PLACEHOLDER_TARGET, "https://portfolio.example.test")
        serialized = json.dumps(run_demo_flow().to_dict(), sort_keys=True)
        self.assertIn("portfolio.example.test", serialized)
        self.assertNotIn("alperen", serialized.lower())


if __name__ == "__main__":
    unittest.main()
