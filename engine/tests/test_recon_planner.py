import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aegis_ev.attack_surface import build_attack_surface_graph
from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget
from aegis_ev.recon_planner import (
    append_recon_plan_audit_events,
    evidence_from_recon_plan,
    plan_safe_recon,
    recon_plan_report_section,
)
from aegis_ev.vuln_intel import map_vulnerability_intelligence


ROOT = Path(__file__).resolve().parents[2]
GRAPH_FIXTURE = ROOT / "fixtures" / "demo" / "demo_attack_surface_input.json"
RECON_FIXTURE = ROOT / "fixtures" / "demo" / "demo_recon_plan_input.json"
KNOWLEDGE_FIXTURES = (
    ROOT / "fixtures" / "knowledge" / "owasp_web_baseline.json",
    ROOT / "fixtures" / "knowledge" / "cwe_baseline.json",
    ROOT / "fixtures" / "knowledge" / "vuln_intel_sample.json",
)
NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-recon-token-1234567890"


def auth(**kwargs):
    payload = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "environment": Environment.STAGING,
        "allowed_impact_levels": [ImpactLevel.GREEN, ImpactLevel.AMBER, ImpactLevel.RED],
        "request_budget": PolicyBudget(max_requests=10),
    }
    payload.update(kwargs)
    return AuthorizationProfile(**payload)


def auth_dict(**kwargs):
    profile = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "environment": "staging",
        "allowed_impact_levels": ["green", "amber", "red"],
        "request_budget": {"max_requests": 10, "max_requests_per_minute": 30, "max_concurrency": 2},
    }
    profile.update(kwargs)
    return profile


def graph_payload(**overrides):
    payload = json.loads(GRAPH_FIXTURE.read_text(encoding="utf-8"))
    payload.update(overrides)
    return payload


def knowledge_records():
    records = []
    for path in KNOWLEDGE_FIXTURES:
        records.extend(json.loads(path.read_text(encoding="utf-8"))["records"])
    return records


def graph():
    return build_attack_surface_graph(graph_payload()).to_dict()


def mapping():
    return map_vulnerability_intelligence(
        {
            "created_at_utc": "2026-01-01T00:00:00+00:00",
            "environment": "staging",
            "attack_surface_graph": graph(),
            "technology_fingerprint": graph_payload()["technology_fingerprint"],
            "knowledge_records": knowledge_records(),
            "evidence": graph_payload()["evidence"],
        }
    ).to_dict()


def fixture_input(**overrides):
    payload = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
    payload.update(overrides)
    return payload


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class SafeReconPlannerTests(unittest.TestCase):
    def test_empty_context_proposes_safe_starting_steps_conservatively(self):
        plan = plan_safe_recon(
            {"created_at_utc": "2026-01-01T00:00:00+00:00", "target": "https://portfolio.example.test"},
            authorization_profile=auth(),
        )
        self.assertEqual(plan.planner_mode, "conservative")
        self.assertIn("safe_fetch_metadata", {step.step_type for step in plan.steps})

    def test_fetch_evidence_absent_proposes_safe_fetch_metadata(self):
        plan = plan_safe_recon(fixture_input(fetch_result=None, evidence=[]), authorization_profile=auth())
        self.assertIn("safe_fetch_metadata", {step.step_type for step in plan.steps})

    def test_header_metadata_present_proposes_analyze_headers(self):
        plan = plan_safe_recon(fixture_input(), authorization_profile=auth())
        self.assertIn("analyze_headers", {step.step_type for step in plan.steps})

    def test_headers_analyzed_but_no_fingerprint_proposes_fingerprint(self):
        payload = fixture_input(header_checks=[{"check_id": "missing_csp", "title": "Missing Content-Security-Policy"}])
        plan = plan_safe_recon(payload, authorization_profile=auth())
        self.assertIn("fingerprint_technology", {step.step_type for step in plan.steps})

    def test_fingerprint_and_endpoints_present_proposes_graph(self):
        payload = {
            "created_at_utc": "2026-01-01T00:00:00+00:00",
            "target": "https://portfolio.example.test",
            "technology_fingerprint": graph_payload()["technology_fingerprint"],
            "endpoints": graph_payload()["endpoints"],
        }
        plan = plan_safe_recon(payload, authorization_profile=auth())
        self.assertIn("build_attack_surface_graph", {step.step_type for step in plan.steps})

    def test_graph_present_proposes_vulnerability_intelligence_mapping(self):
        plan = plan_safe_recon({"target": "https://portfolio.example.test", "attack_surface_graph": graph()}, authorization_profile=auth())
        self.assertIn("map_vulnerability_intelligence", {step.step_type for step in plan.steps})

    def test_candidate_findings_present_proposes_report_and_retest_planning(self):
        plan = plan_safe_recon(fixture_input(), authorization_profile=auth())
        step_types = {step.step_type for step in plan.steps}
        self.assertIn("generate_report", step_types)
        self.assertIn("retest_after_fix", step_types)

    def test_admin_auth_surface_plus_missing_controls_proposes_human_review_not_active_execution(self):
        plan = plan_safe_recon({"target": "https://portfolio.example.test", "attack_surface_graph": graph()}, authorization_profile=auth())
        by_type = {step.step_type: step for step in plan.steps}
        self.assertEqual(by_type["human_review"].status, "requires_approval")
        self.assertEqual(by_type["blocked_intrusive_validation"].status, "blocked")
        rendered = json.dumps(plan.to_dict(), sort_keys=True).lower()
        self.assertNotIn("sqlmap", rendered)
        self.assertNotIn("metasploit", rendered)

    def test_amber_red_future_steps_are_approval_required_or_blocked(self):
        plan = plan_safe_recon(
            {
                "target": "https://portfolio.example.test",
                "future_steps": [
                    {"step_type": "human_review", "impact_level": "amber", "title": "Review", "description": "Review", "rationale": "Owner review"},
                    {"step_type": "blocked_intrusive_validation", "impact_level": "red", "title": "Blocked", "description": "Blocked", "rationale": "Out of scope"},
                ],
            },
            authorization_profile=auth(),
        )
        statuses = {step.step_type: step.status for step in plan.steps}
        self.assertEqual(statuses["human_review"], "requires_approval")
        self.assertEqual(statuses["blocked_intrusive_validation"], "blocked")

    def test_unknown_impact_is_blocked(self):
        plan = plan_safe_recon(
            {"target": "https://portfolio.example.test", "future_steps": [{"step_type": "unknown", "title": "Unknown", "description": "Unknown", "rationale": "Unknown"}]},
            authorization_profile=auth(),
        )
        self.assertIn("blocked", {step.status for step in plan.steps if step.step_type == "unknown"})

    def test_out_of_scope_target_denied_before_planning_execution(self):
        plan = plan_safe_recon({"target": "https://evil.test"}, authorization_profile=auth())
        fetch = next(step for step in plan.steps if step.step_type == "safe_fetch_metadata")
        self.assertEqual(fetch.status, "blocked")
        self.assertEqual(fetch.required_policy_decision["decision_code"], "target_out_of_scope")

    def test_planner_does_not_execute_network_or_tool_calls(self):
        import inspect
        import aegis_ev.recon_planner as recon_planner

        source = inspect.getsource(recon_planner)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("import requests", source)

    def test_adapter_availability_warnings_are_non_fatal(self):
        from aegis_ev.adapters.framework import AdapterRegistry

        plan = plan_safe_recon(fixture_input(), authorization_profile=auth(), adapter_registry=AdapterRegistry())
        self.assertTrue(plan.warnings)
        self.assertTrue(plan.steps)

    def test_approval_is_never_auto_granted(self):
        plan = plan_safe_recon({"target": "https://portfolio.example.test", "attack_surface_graph": graph()}, authorization_profile=auth())
        self.assertFalse(plan.metadata["approval_auto_granted"])
        for step in plan.approval_required_steps:
            self.assertFalse(step.metadata["approval_request"]["auto_approved"])

    def test_deterministic_step_ids_and_json_serialization(self):
        first = plan_safe_recon(fixture_input(), authorization_profile=auth()).serialize()
        second = plan_safe_recon(fixture_input(), authorization_profile=auth()).serialize()
        self.assertEqual(first, second)
        plan = plan_safe_recon(fixture_input(), authorization_profile=auth())
        self.assertEqual([step.step_id for step in plan.steps], sorted(step.step_id for step in plan.steps))

    def test_no_raw_secrets_in_plan_output(self):
        payload = fixture_input(metadata={"token": SECRET_VALUE})
        payload["headers"] = {"Authorization": "Bearer " + SECRET_VALUE}
        serialized = plan_safe_recon(payload, authorization_profile=auth()).serialize()
        self.assertNotIn(SECRET_VALUE, serialized)

    def test_no_unsafe_instructions_in_generated_plan(self):
        rendered = json.dumps(plan_safe_recon({"target": "https://portfolio.example.test", "attack_surface_graph": graph()}, authorization_profile=auth()).to_dict(), sort_keys=True).lower()
        self.assertNotIn("reverse shell", rendered)
        self.assertNotIn("shell payload", rendered)
        self.assertNotIn("dump credentials", rendered)

    def test_evidence_generated_from_recon_plan(self):
        plan = plan_safe_recon(fixture_input(), authorization_profile=auth())
        evidence = evidence_from_recon_plan(plan)
        self.assertEqual(evidence.source_type, EvidenceSourceType.RECON_PLANNER.value)
        self.assertIn(str(len(plan.steps)), evidence.summary)

    def test_audit_safe_event_generated_for_plan(self):
        plan = plan_safe_recon(fixture_input(), authorization_profile=auth())
        events = append_recon_plan_audit_events(plan)
        self.assertEqual(events[0].event_type, "recon_plan_created")
        self.assertTrue([event for event in events if event.event_type == "recon_step_proposed"])

    def test_report_section_helper(self):
        section = recon_plan_report_section(plan_safe_recon(fixture_input(), authorization_profile=auth()))
        self.assertEqual(section["title"], "Recon Plan Summary")
        self.assertIn("proposed_safe_next_steps", section)

    def test_cli_plan_safe_recon_returns_parseable_json(self):
        code, response = run_cli(
            ["plan-safe-recon"],
            {
                "target": "https://portfolio.example.test",
                "authorization_profile": auth_dict(),
                "planner_input": fixture_input(),
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("plan", response["result"])
        self.assertIn("evidence", response["result"])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["plan-safe-recon"], {"target": "https://portfolio.example.test"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_no_real_network_side_effects_no_api_keys_no_real_portfolio_url(self):
        import inspect
        import aegis_ev.recon_planner as recon_planner

        source = inspect.getsource(recon_planner)
        self.assertNotIn("alperenmanas", source.lower())
        self.assertNotIn("api_key", json.dumps(plan_safe_recon(fixture_input(), authorization_profile=auth()).to_dict(), sort_keys=True).lower())


if __name__ == "__main__":
    unittest.main()
