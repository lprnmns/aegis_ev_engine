import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aegis_ev.evidence import EvidenceSourceType, FindingRecord, FindingStatus, RetestStatus
from aegis_ev.main import main
from aegis_ev.remediation import (
    build_remediation_audit_event,
    compare_retest_results,
    create_retest_plan,
    evidence_from_remediation_guidance,
    evidence_from_retest_plan,
    evidence_from_retest_result,
    generate_remediation_guidance,
    remediation_retest_report_section,
    update_finding_from_retest,
)


ROOT = Path(__file__).resolve().parents[2]
FINDINGS_FIXTURE = ROOT / "fixtures" / "demo" / "demo_remediation_findings.json"
BEFORE_HEADERS = ROOT / "fixtures" / "demo" / "demo_retest_before_headers.json"
AFTER_FIXED_HEADERS = ROOT / "fixtures" / "demo" / "demo_retest_after_headers_fixed.json"
AFTER_UNCHANGED_HEADERS = ROOT / "fixtures" / "demo" / "demo_retest_after_headers_unchanged.json"


def fixture():
    return json.loads(FINDINGS_FIXTURE.read_text(encoding="utf-8"))


def findings():
    return fixture()["findings"]


def finding(finding_id):
    return next(item for item in findings() if item["finding_id"] == finding_id)


def headers(path):
    return json.loads(path.read_text(encoding="utf-8"))["headers"]


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class RemediationRetestTests(unittest.TestCase):
    def test_remediation_guidance_generated_for_missing_csp(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_csp")})
        self.assertIn("Content-Security-Policy", " ".join(guidance.configuration_examples))
        self.assertIn("default-src", " ".join(guidance.configuration_examples))

    def test_remediation_guidance_generated_for_missing_clickjacking_controls(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_clickjacking")})
        joined = " ".join(guidance.configuration_examples)
        self.assertIn("X-Frame-Options", joined)
        self.assertIn("frame-ancestors", joined)

    def test_remediation_guidance_generated_for_missing_nosniff(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_nosniff")})
        self.assertIn("nosniff", " ".join(guidance.configuration_examples))

    def test_remediation_guidance_generated_for_missing_referrer_policy(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_referrer")})
        self.assertIn("Referrer-Policy", " ".join(guidance.configuration_examples))

    def test_remediation_guidance_generated_for_missing_permissions_policy(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_permissions")})
        self.assertIn("Permissions-Policy", " ".join(guidance.configuration_examples))

    def test_remediation_guidance_generated_for_disclosure_headers(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_powered_by_disclosure")})
        self.assertIn("X-Powered-By", guidance.summary + " ".join(guidance.configuration_examples))

    def test_nextjs_vercel_specific_guidance_only_when_evidence_supports_it(self):
        without = generate_remediation_guidance({"finding": finding("finding_demo_missing_csp")})
        with_evidence = generate_remediation_guidance({"finding": finding("finding_demo_missing_csp"), "technology_fingerprint": fixture()["technology_fingerprint"]})
        self.assertNotIn("Next.js", " ".join(without.configuration_examples))
        self.assertIn("Next.js", " ".join(with_evidence.configuration_examples))
        self.assertIn("Vercel", " ".join(with_evidence.configuration_examples))

    def test_retest_plan_generated_from_findings(self):
        plan = create_retest_plan({"findings": findings(), "target": "https://portfolio.example.test"})
        self.assertEqual(len(plan.retest_steps), len(findings()))
        self.assertTrue(plan.safe_mode_required)

    def test_retest_plan_uses_safe_head_metadata_header_checks_only(self):
        plan = create_retest_plan({"findings": findings(), "target": "https://portfolio.example.test"})
        self.assertEqual(plan.allowed_methods, ("HEAD",))
        self.assertTrue(all(step.safe_method == "HEAD" and step.impact_level == "green" for step in plan.retest_steps))
        rendered = json.dumps(plan.to_dict()).lower()
        self.assertNotIn("scanner", rendered)
        self.assertNotIn("crawler", rendered)

    def test_missing_csp_resolved_when_after_header_present(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        self.assertEqual(result.finding_results[0].result, "resolved")
        self.assertEqual(result.finding_results[0].new_retest_status, "appears_resolved")

    def test_missing_nosniff_resolved_when_after_header_equals_nosniff(self):
        result = _compare_single("finding_demo_missing_nosniff", AFTER_FIXED_HEADERS)
        self.assertEqual(result.finding_results[0].result, "resolved")

    def test_missing_referrer_policy_resolved_when_after_header_present(self):
        result = _compare_single("finding_demo_missing_referrer", AFTER_FIXED_HEADERS)
        self.assertEqual(result.finding_results[0].result, "resolved")

    def test_unchanged_findings_remain_still_present(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_UNCHANGED_HEADERS)
        self.assertEqual(result.finding_results[0].result, "unchanged")
        self.assertEqual(result.finding_results[0].new_retest_status, "still_present")

    def test_ambiguous_disclosure_reduction_requires_human_review(self):
        before = {"Server": "DemoServer/1.0"}
        after = {"Server": "DemoServer"}
        result = compare_retest_results(
            {
                "findings": [finding("finding_demo_server_disclosure")],
                "before_headers": before,
                "after_headers": after,
            }
        )
        self.assertEqual(result.finding_results[0].result, "inconclusive")
        self.assertTrue(result.finding_results[0].requires_human_review)

    def test_retest_does_not_mark_confirmed_or_delete_finding(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        original = FindingRecord(**finding("finding_demo_missing_csp"))
        updated = update_finding_from_retest(original, result.finding_results[0])
        self.assertEqual(updated.status, FindingStatus.CANDIDATE.value)
        self.assertNotEqual(updated.status, FindingStatus.CONFIRMED.value)
        self.assertEqual(updated.finding_id, original.finding_id)

    def test_evidence_generated_from_retest_result(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        evidence = evidence_from_retest_result(result)
        self.assertEqual(evidence.source_type, EvidenceSourceType.REMEDIATION_RETEST.value)
        self.assertIn("appears resolved", evidence.summary)

    def test_audit_event_generated_from_retest_result(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        event = build_remediation_audit_event(
            "retest_completed",
            target=result.target,
            metadata={"retest_result_id": result.retest_result_id},
            timestamp_utc="2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(event.event_type, "retest_completed")
        self.assertFalse(event.metadata["body_stored"])

    def test_report_section_generated_for_remediation_retest(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_csp")})
        plan = create_retest_plan({"findings": [finding("finding_demo_missing_csp")]})
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        section = remediation_retest_report_section(guidance=[guidance], plan=plan, result=result)
        self.assertEqual(section["title"], "Remediation and Retest Summary")
        self.assertIn("before_after_summary", section)

    def test_evidence_generated_for_guidance_and_plan(self):
        guidance = generate_remediation_guidance({"finding": finding("finding_demo_missing_csp")})
        plan = create_retest_plan({"findings": [finding("finding_demo_missing_csp")]})
        self.assertEqual(evidence_from_remediation_guidance(guidance).source_type, EvidenceSourceType.REMEDIATION_RETEST.value)
        self.assertEqual(evidence_from_retest_plan(plan).source_type, EvidenceSourceType.REMEDIATION_RETEST.value)

    def test_cli_generate_remediation_guidance_returns_parseable_json(self):
        code, response = run_cli(["generate-remediation-guidance"], {"finding": finding("finding_demo_missing_csp")})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("guidance", response["result"])

    def test_cli_create_retest_plan_returns_parseable_json(self):
        code, response = run_cli(["create-retest-plan"], {"findings": [finding("finding_demo_missing_csp")]})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("retest_plan", response["result"])

    def test_cli_compare_retest_results_returns_parseable_json(self):
        plan = create_retest_plan({"findings": [finding("finding_demo_missing_csp")]}).to_dict()
        code, response = run_cli(
            ["compare-retest-results"],
            {
                "retest_plan": plan,
                "findings": [finding("finding_demo_missing_csp")],
                "before_headers": headers(BEFORE_HEADERS),
                "after_headers": headers(AFTER_FIXED_HEADERS),
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("retest_result", response["result"])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["create-retest-plan"], {"findings": []})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_no_real_network_api_keys_or_portfolio_url(self):
        import inspect
        import aegis_ev.remediation as remediation

        source = inspect.getsource(remediation)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("alperenmanas", source.lower())

    def test_no_unsafe_instructions_in_outputs_or_fixtures(self):
        result = _compare_single("finding_demo_missing_csp", AFTER_FIXED_HEADERS)
        rendered = json.dumps(result.to_dict()).lower() + FINDINGS_FIXTURE.read_text(encoding="utf-8").lower()
        self.assertNotIn("reverse shell", rendered)
        self.assertNotIn("shell payload", rendered)
        self.assertNotIn("dump credentials", rendered)


def _compare_single(finding_id, after_fixture):
    target_finding = finding(finding_id)
    plan = create_retest_plan({"findings": [target_finding], "target": "https://portfolio.example.test"})
    return compare_retest_results(
        {
            "retest_plan": plan.to_dict(),
            "findings": [target_finding],
            "before_headers": headers(BEFORE_HEADERS),
            "after_headers": headers(after_fixture),
            "evidence_ids": ["evidence_retest_after"],
        }
    )


if __name__ == "__main__":
    unittest.main()
