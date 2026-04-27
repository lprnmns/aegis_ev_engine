import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from aegis_ev.evidence import FindingStatus, VerificationState
from aegis_ev.http_fetch import SafeHttpTransportResponse
from aegis_ev.portfolio_demo import PortfolioDemoInput, run_portfolio_demo, run_portfolio_demo_from_payload


EXAMPLE_INPUT = Path(__file__).resolve().parents[2] / "fixtures" / "demo" / "portfolio_demo_input.example.json"
SECRET_VALUE = "not-a-real-portfolio-token-1234567890"


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
    data.update(
        {
            "output_dir": None,
            "write_outputs": False,
            "include_report_contents": True,
            "now": "2026-01-01T00:00:00+00:00",
        }
    )
    data.update(overrides)
    return data


def good_transport():
    return CountingTransport(
        [
            SafeHttpTransportResponse(
                status_code=200,
                final_url="https://portfolio.example.test",
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "DemoServer/1.0",
                    "Set-Cookie": "sid=" + SECRET_VALUE,
                },
                elapsed_ms=7,
            )
        ]
    )


class PortfolioDemoTests(unittest.TestCase):
    def test_example_portfolio_input_parses(self):
        data = json.loads(EXAMPLE_INPUT.read_text(encoding="utf-8"))
        model = PortfolioDemoInput.from_payload(data)
        self.assertEqual(model.target_url, "https://portfolio.example.test")
        self.assertTrue(model.owner_authorization_attestation)

    def test_missing_attestation_denied_before_network(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(owner_authorization_attestation=False))

    def test_safe_mode_false_denied_before_network(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(safe_mode=False))

    def test_attestation_string_is_denied(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(owner_authorization_attestation="true"))

    def test_auth_headers_are_rejected(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(request_headers={"Authorization": "Bearer " + SECRET_VALUE}))

    def test_out_of_scope_target_denied_before_network(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(target_url="https://outside.example.test"))

    def test_unsupported_scheme_denied_before_network(self):
        with self.assertRaises(ValueError):
            PortfolioDemoInput.from_payload(payload(target_url="ftp://portfolio.example.test"))

    def test_valid_placeholder_target_with_fake_transport_completes(self):
        transport = good_transport()
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=transport)
        self.assertEqual(result.demo_id, "authorized_portfolio_demo_v1")
        self.assertEqual(result.fetch_status["status_code"], 200)
        self.assertEqual(transport.calls, [("HEAD", "https://portfolio.example.test", 5)])
        self.assertFalse(result.live_request_performed)

    def test_fake_fetch_result_feeds_header_checks(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        self.assertGreater(result.header_check_count, 0)
        self.assertIn("Missing Content-Security-Policy", result.reports["markdown"])

    def test_evidence_created(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        self.assertGreater(result.evidence_count, 0)
        self.assertTrue(result.evidence_ids)

    def test_candidate_findings_created(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        self.assertGreater(result.finding_count, 0)
        self.assertTrue(result.finding_ids)

    def test_findings_are_not_confirmed_by_default(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        report = json.loads(result.reports["json"])
        statuses = {finding["status"] for finding in report["findings"]}
        verification_states = {finding["verification_state"] for finding in report["findings"]}
        self.assertNotIn(FindingStatus.CONFIRMED.value, statuses)
        self.assertNotIn(VerificationState.VERIFIED.value, verification_states)

    def test_audit_verification_passes(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        self.assertTrue(result.audit_verification_status["valid"])
        self.assertGreaterEqual(result.audit_verification_status["event_count"], 5)

    def test_markdown_report_generated(self):
        markdown = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport()).reports["markdown"]
        self.assertIn("# Aegis EV Portfolio Demo Security Validation Report", markdown)

    def test_json_report_generated(self):
        report = json.loads(run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport()).reports["json"])
        self.assertEqual(report["report_id"], "report_authorized_portfolio_demo")

    def test_report_contains_authorized_demo_disclaimer(self):
        markdown = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport()).reports["markdown"]
        self.assertIn("Authorized owner-provided demo", markdown)
        self.assertIn("No crawling, fuzzing", markdown)
        self.assertIn("not confirmed exploitability", markdown.lower())

    def test_report_contains_no_raw_secrets(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("redacted", serialized)

    def test_output_dir_writing_works_with_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_portfolio_demo(
                PortfolioDemoInput.from_payload(payload(output_dir=tmp, write_outputs=True, include_report_contents=False)),
                transport=good_transport(),
            )
            self.assertTrue(Path(result.report_paths["markdown"]).exists())
            self.assertTrue(Path(result.report_paths["json"]).exists())
            self.assertEqual(result.reports, {})
            json.loads(Path(result.report_paths["json"]).read_text(encoding="utf-8"))

    def test_cli_run_portfolio_demo_returns_parseable_json(self):
        data = payload(
            transport_fixture={
                "responses": [
                    {
                        "status_code": 200,
                        "final_url": "https://portfolio.example.test",
                        "headers": {"Content-Type": "text/html", "Set-Cookie": "sid=" + SECRET_VALUE},
                    }
                ]
            }
        )
        completed = subprocess.run(
            [sys.executable, "-m", "aegis_ev.main", "run-portfolio-demo"],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        response = json.loads(completed.stdout)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["demo"]["fetch_status"]["status_code"], 200)
        self.assertNotIn(SECRET_VALUE, completed.stdout)

    def test_cli_invalid_input_returns_structured_error(self):
        completed = subprocess.run(
            [sys.executable, "-m", "aegis_ev.main", "run-portfolio-demo"],
            input=json.dumps(payload(owner_authorization_attestation=False)),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        response = json.loads(completed.stdout)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_no_real_network_side_effects(self):
        import aegis_ev.portfolio_demo as portfolio_demo

        source = inspect.getsource(portfolio_demo)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)

    def test_no_real_network_call_happens_when_policy_denies(self):
        with self.assertRaises(ValueError):
            run_portfolio_demo_from_payload(payload(target_url="https://outside.example.test", transport_fixture={"responses": [{"status_code": 200}]}))

    def test_no_real_portfolio_url_hardcoded(self):
        serialized = json.dumps(run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport()).to_dict(), sort_keys=True)
        self.assertIn("portfolio.example.test", serialized)
        self.assertNotIn("alperen", serialized.lower())

    def test_no_api_keys_required(self):
        result = run_portfolio_demo(PortfolioDemoInput.from_payload(payload()), transport=good_transport())
        self.assertNotIn("api_key", json.dumps(result.to_dict(), sort_keys=True).lower())


if __name__ == "__main__":
    unittest.main()
