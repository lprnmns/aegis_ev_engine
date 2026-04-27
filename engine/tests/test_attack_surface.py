import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aegis_ev.attack_surface import (
    attack_surface_report_section,
    build_attack_surface_graph,
    evidence_from_attack_surface_graph,
)
from aegis_ev.evidence import EvidenceSourceType
from aegis_ev.main import main


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-graph-token-1234567890"
FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "demo" / "demo_attack_surface_input.json"


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


def fixture_payload(**overrides):
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data.update(overrides)
    return data


def run_cli(argv, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


class AttackSurfaceGraphTests(unittest.TestCase):
    def test_graph_builder_creates_target_domain_url_nodes(self):
        graph = build_attack_surface_graph(fixture_payload())
        types = {node.node_type for node in graph.nodes}
        self.assertIn("url", types)
        self.assertIn("domain", types)
        self.assertGreaterEqual(graph.target_count, 2)

    def test_endpoint_inventory_creates_endpoint_nodes(self):
        graph = build_attack_surface_graph(fixture_payload())
        endpoints = [node for node in graph.nodes if node.node_type == "endpoint"]
        self.assertEqual(len(endpoints), 2)
        self.assertIn("GET /admin/login", {node.label for node in endpoints})

    def test_technology_fingerprint_creates_technology_framework_platform_nodes(self):
        graph = build_attack_surface_graph(fixture_payload())
        labels = {node.label for node in graph.nodes}
        types = {node.node_type for node in graph.nodes}
        self.assertIn("Next.js", labels)
        self.assertIn("Vercel", labels)
        self.assertIn("framework", types)
        self.assertIn("hosting", types)

    def test_missing_controls_create_missing_control_nodes(self):
        graph = build_attack_surface_graph(fixture_payload())
        missing = {node.label for node in graph.nodes if node.node_type == "missing_control"}
        self.assertIn("Content-Security-Policy", missing)
        self.assertIn("X-Frame-Options", missing)

    def test_admin_auth_api_upload_paths_create_surface_hint_nodes(self):
        graph = build_attack_surface_graph(
            fixture_payload(endpoints=fixture_payload()["endpoints"] + [{"method": "POST", "path": "/upload/avatar"}])
        )
        types = {node.node_type for node in graph.nodes}
        self.assertIn("admin_surface", types)
        self.assertIn("auth_surface", types)
        self.assertIn("api_surface", types)
        self.assertIn("upload_surface", types)

    def test_risk_hypotheses_become_hypothesis_nodes(self):
        graph = build_attack_surface_graph(fixture_payload())
        hypotheses = [node for node in graph.nodes if node.node_type == "risk_hypothesis"]
        self.assertEqual(len(hypotheses), 1)
        self.assertEqual(hypotheses[0].metadata["status"], "hypothesis")

    def test_evidence_records_link_to_nodes_and_edges(self):
        graph = build_attack_surface_graph(fixture_payload())
        self.assertTrue([node for node in graph.nodes if node.node_type == "evidence"])
        self.assertTrue([edge for edge in graph.edges if edge.edge_type == "backed_by_evidence"])

    def test_stable_node_ids_edge_ids_and_deterministic_json(self):
        first = build_attack_surface_graph(fixture_payload()).serialize()
        second = build_attack_surface_graph(fixture_payload()).serialize()
        self.assertEqual(first, second)
        graph = build_attack_surface_graph(fixture_payload())
        self.assertEqual([node.node_id for node in graph.nodes], sorted(node.node_id for node in graph.nodes))
        self.assertEqual([edge.edge_id for edge in graph.edges], sorted(edge.edge_id for edge in graph.edges))

    def test_graph_summary_counts_are_correct(self):
        graph = build_attack_surface_graph(fixture_payload())
        self.assertEqual(graph.endpoint_count, 2)
        self.assertGreaterEqual(graph.technology_count, 2)
        self.assertEqual(graph.hypothesis_count, 1)
        self.assertEqual(graph.risk_summary["endpoints_by_method"]["GET"], 1)
        self.assertEqual(graph.risk_summary["endpoints_by_method"]["POST"], 1)

    def test_prioritization_hints_are_conservative(self):
        graph = build_attack_surface_graph(fixture_payload())
        hints = graph.risk_summary["priority_hints"]
        self.assertTrue(hints)
        self.assertEqual({hint["status"] for hint in hints}, {"priority_hint"})

    def test_production_environment_changes_priority_but_not_confirmation(self):
        payload = fixture_payload()
        payload["project"]["environment"] = "production"
        graph = build_attack_surface_graph(payload)
        self.assertIn("high", {hint["priority"] for hint in graph.risk_summary["priority_hints"]})
        self.assertFalse(graph.metadata["confirmed_findings_created"])

    def test_no_confirmed_findings_are_created(self):
        graph = build_attack_surface_graph(fixture_payload())
        self.assertFalse(graph.metadata["confirmed_findings_created"])
        finding_nodes = [node for node in graph.nodes if node.node_type == "finding_candidate"]
        self.assertFalse(finding_nodes)

    def test_sensitive_values_are_redacted(self):
        payload = fixture_payload(metadata={"token": SECRET_VALUE})
        payload["evidence"][0]["structured_data"] = {"Authorization": "Bearer " + SECRET_VALUE}
        graph = build_attack_surface_graph(payload)
        serialized = json.dumps(graph.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)

    def test_no_raw_cookies_auth_headers_tokens_in_graph_json(self):
        payload = fixture_payload(fetch_result={"headers": {"Set-Cookie": "sid=" + SECRET_VALUE}})
        serialized = build_attack_surface_graph(payload).serialize()
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertNotIn("Set-Cookie", serialized)

    def test_evidence_generated_from_graph(self):
        graph = build_attack_surface_graph(fixture_payload())
        evidence = evidence_from_attack_surface_graph(graph)
        self.assertEqual(evidence.source_type, EvidenceSourceType.ATTACK_SURFACE_GRAPH.value)
        self.assertIn("Graph contains", evidence.summary)

    def test_report_section_helper(self):
        section = attack_surface_report_section(build_attack_surface_graph(fixture_payload()))
        self.assertEqual(section["title"], "Attack Surface Summary")
        self.assertIn("missing_controls", section)

    def test_cli_build_attack_surface_graph_returns_parseable_json(self):
        code, response = run_cli(
            ["build-attack-surface-graph"],
            {"target": "https://portfolio.example.test", "authorization_profile": auth(), "graph_input": fixture_payload()},
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("graph", response["result"])
        self.assertIn("evidence", response["result"])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["build-attack-surface-graph"], {"target": "https://portfolio.example.test"})
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
                action_id="graph",
                adapter_id="attack_surface_graph",
                target="https://portfolio.example.test",
                action="build_attack_surface_graph",
                arguments={"graph_input": fixture_payload()},
                requested_impact_level=ImpactLevel.GREEN,
                actor="tester",
                authorization_profile=profile,
            )
        )
        self.assertTrue(plan.allowed)
        self.assertFalse(default_registry().get("attack_surface_graph").metadata.requires_network)

    def test_no_real_network_side_effects_no_api_keys_no_real_portfolio_url(self):
        import inspect
        import aegis_ev.attack_surface as attack_surface

        source = inspect.getsource(attack_surface)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("api_key", json.dumps(build_attack_surface_graph(fixture_payload()).to_dict(), sort_keys=True).lower())
        self.assertNotIn("alperenmanas", source.lower())


if __name__ == "__main__":
    unittest.main()
