import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aegis_ev.attack_surface import build_attack_surface_graph
from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main
from aegis_ev.vuln_intel import (
    evidence_from_vulnerability_mapping,
    findings_from_vulnerability_mapping,
    knowledge_record_from_dict,
    load_knowledge_records,
    map_vulnerability_intelligence,
    vulnerability_intelligence_report_section,
)


ROOT = Path(__file__).resolve().parents[2]
GRAPH_FIXTURE = ROOT / "fixtures" / "demo" / "demo_attack_surface_input.json"
KNOWLEDGE_FIXTURES = (
    ROOT / "fixtures" / "knowledge" / "owasp_web_baseline.json",
    ROOT / "fixtures" / "knowledge" / "cwe_baseline.json",
    ROOT / "fixtures" / "knowledge" / "vuln_intel_sample.json",
)
NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-vuln-intel-token-1234567890"


def auth(**kwargs):
    payload = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "environment": "staging",
        "allowed_impact_levels": ["green", "amber", "red"],
        "request_budget": {"max_requests": 10, "max_requests_per_minute": 30, "max_concurrency": 2},
    }
    payload.update(kwargs)
    return payload


def graph_payload(**overrides):
    payload = json.loads(GRAPH_FIXTURE.read_text(encoding="utf-8"))
    payload.update(overrides)
    return payload


def knowledge_records():
    records = []
    for path in KNOWLEDGE_FIXTURES:
        records.extend(json.loads(path.read_text(encoding="utf-8"))["records"])
    return records


def mapping_input(**overrides):
    graph = build_attack_surface_graph(graph_payload()).to_dict()
    payload = {
        "created_at_utc": "2026-01-01T00:00:00+00:00",
        "environment": "staging",
        "attack_surface_graph": graph,
        "technology_fingerprint": graph_payload()["technology_fingerprint"],
        "knowledge_records": knowledge_records(),
        "evidence": graph_payload()["evidence"],
    }
    payload.update(overrides)
    return payload


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class VulnerabilityIntelTests(unittest.TestCase):
    def test_knowledge_record_validation(self):
        record = knowledge_record_from_dict(knowledge_records()[0])
        self.assertEqual(record.record_type, "owasp")
        self.assertTrue(record.record_id)

    def test_invalid_record_type_denied(self):
        record = dict(knowledge_records()[0])
        record["record_type"] = "live_feed"
        with self.assertRaises(ValueError):
            knowledge_record_from_dict(record)

    def test_mapping_missing_csp_to_owasp_and_cwe_records(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        record_ids = {match.knowledge_record_id for match in mapping.matches}
        self.assertIn("owasp-web-a05-missing-csp", record_ids)
        self.assertIn("cwe-693-missing-security-control", record_ids)

    def test_mapping_missing_clickjacking_protection_to_cwe_1021_style_record(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        matches = {match.knowledge_record_id: match for match in mapping.matches}
        self.assertIn("cwe-1021-clickjacking-control", matches)
        self.assertIn("CWE", matches["cwe-1021-clickjacking-control"].knowledge_record_id.upper())

    def test_mapping_api_surface_without_auth_indicators_to_api_risk_hypothesis(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        match = next(item for item in mapping.matches if item.knowledge_record_id == "owasp-api-auth-indicator-review")
        self.assertIn(match.priority, {"medium", "high"})
        self.assertFalse(match.metadata["confirmed_vulnerability"])

    def test_mapping_admin_surface_and_missing_controls_increases_priority(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        match = next(item for item in mapping.matches if item.knowledge_record_id == "cwe-1021-clickjacking-control")
        self.assertEqual(match.priority, "high")
        self.assertTrue(match.requires_human_review)

    def test_production_environment_increases_priority_but_does_not_confirm(self):
        payload = mapping_input(environment="production")
        mapping = map_vulnerability_intelligence(payload)
        csp = next(item for item in mapping.matches if item.knowledge_record_id == "owasp-web-a05-missing-csp")
        self.assertEqual(csp.priority, "high")
        self.assertFalse(mapping.metadata["confirmed_findings_created"])

    def test_kev_like_fixture_increases_priority(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        match = next(item for item in mapping.matches if item.knowledge_record_id == "kev-sample-admin-missing-frame-control")
        self.assertEqual(match.priority, "high")
        self.assertTrue(match.requires_human_review)

    def test_epss_like_fixture_increases_priority(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        match = next(item for item in mapping.matches if item.knowledge_record_id == "epss-sample-api-auth-review")
        self.assertEqual(match.priority, "high")

    def test_low_confidence_fingerprint_keeps_match_conservative(self):
        graph_data = graph_payload()
        graph_data["technology_fingerprint"]["detected_technologies"].append(
            {
                "name": "Uncertain Framework",
                "category": "frontend_framework",
                "confidence": "low",
                "evidence_source": "supplied",
                "evidence_summary": "Low confidence marker.",
            }
        )
        graph = build_attack_surface_graph(graph_data).to_dict()
        mapping = map_vulnerability_intelligence(
            mapping_input(attack_surface_graph=graph, technology_fingerprint=graph_data["technology_fingerprint"])
        )
        cve = next(item for item in mapping.matches if item.knowledge_record_id == "cve-sample-framework-disclosure")
        self.assertIn(cve.priority, {"low", "medium"})
        self.assertIn(cve.confidence, {"low", "medium"})

    def test_deterministic_match_ids_and_json_serialization(self):
        first = map_vulnerability_intelligence(mapping_input()).serialize()
        second = map_vulnerability_intelligence(mapping_input()).serialize()
        self.assertEqual(first, second)
        mapping = map_vulnerability_intelligence(mapping_input())
        self.assertEqual([item.match_id for item in mapping.matches], sorted(item.match_id for item in mapping.matches))

    def test_no_confirmed_findings_created(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        self.assertFalse(mapping.metadata["confirmed_findings_created"])
        self.assertEqual(findings_from_vulnerability_mapping(mapping), [])

    def test_no_offensive_content_in_records(self):
        serialized = json.dumps(knowledge_records(), sort_keys=True).lower()
        self.assertNotIn("reverse shell", serialized)
        self.assertNotIn("metasploit", serialized)
        self.assertNotIn("sqlmap", serialized)
        self.assertNotIn("rce proof", serialized)

    def test_no_raw_secrets_in_mapping_output(self):
        payload = mapping_input()
        payload["attack_surface_graph"]["nodes"].append(
            {
                "node_id": "node_secret",
                "node_type": "missing_control",
                "label": "Content-Security-Policy",
                "metadata": {"token": SECRET_VALUE},
                "evidence_ids": ["evidence_secret"],
            }
        )
        serialized = map_vulnerability_intelligence(payload).serialize()
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertNotIn("api_key", serialized.lower())

    def test_evidence_generated_from_mapping_result(self):
        mapping = map_vulnerability_intelligence(mapping_input())
        evidence = evidence_from_vulnerability_mapping(mapping)
        self.assertEqual(evidence.source_type, EvidenceSourceType.VULNERABILITY_INTELLIGENCE.value)
        self.assertIn(str(mapping.match_count), evidence.summary)

    def test_report_section_helper(self):
        section = vulnerability_intelligence_report_section(map_vulnerability_intelligence(mapping_input()))
        self.assertEqual(section["title"], "Vulnerability Intelligence Summary")
        self.assertIn("knowledge_matches", section)

    def test_cli_map_vulnerability_intelligence_returns_parseable_json(self):
        code, response = run_cli(
            ["map-vulnerability-intelligence"],
            {
                "target": "https://portfolio.example.test",
                "authorization_profile": auth(),
                "mapping_input": mapping_input(),
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("mapping", response["result"])
        self.assertIn("evidence", response["result"])
        self.assertEqual(response["result"]["findings"], [])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["map-vulnerability-intelligence"], {"target": "https://portfolio.example.test"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_adapter_dry_run_planning_does_not_call_network(self):
        from aegis_ev.adapters import AdapterPlanner, default_registry
        from aegis_ev.adapters.framework import ToolActionRequest
        from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget

        profile = AuthorizationProfile(
            owner="tester",
            allowed_domains=["portfolio.example.test"],
            allowed_cidrs=[],
            valid_from=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=1),
            environment=Environment.STAGING,
            allowed_impact_levels=[ImpactLevel.GREEN],
            request_budget=PolicyBudget(max_requests=5),
        )
        plan = AdapterPlanner(default_registry()).plan(
            ToolActionRequest(
                action_id="vuln-intel",
                adapter_id="vulnerability_intelligence",
                target="https://portfolio.example.test",
                action="map_vulnerability_intelligence",
                arguments={"mapping_input": mapping_input()},
                requested_impact_level=ImpactLevel.GREEN,
                actor="tester",
                authorization_profile=profile,
            )
        )
        self.assertTrue(plan.allowed)
        self.assertFalse(default_registry().get("vulnerability_intelligence").metadata.requires_network)

    def test_no_real_network_side_effects_no_api_keys_no_real_portfolio_url(self):
        import inspect
        import aegis_ev.vuln_intel as vuln_intel

        source = inspect.getsource(vuln_intel)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("alperenmanas", source.lower())
        self.assertNotIn("api_key", json.dumps(map_vulnerability_intelligence(mapping_input()).to_dict(), sort_keys=True).lower())


if __name__ == "__main__":
    unittest.main()
