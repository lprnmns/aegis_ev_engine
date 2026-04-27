import inspect
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from aegis_ev.evidence import EvidenceSourceType, FindingStatus
from aegis_ev.fingerprinting import (
    MAX_HTML_SNIPPET_BYTES,
    TechnologyFingerprintInput,
    evidence_from_fingerprint,
    fingerprint_from_fetch_result,
    fingerprint_technology,
    findings_from_fingerprint,
)
from aegis_ev.http_fetch import SafeHttpFetchResult
from aegis_ev.main import main


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-fingerprint-token-1234567890"


def auth(**kwargs):
    payload = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["example.com"],
        "allowed_cidrs": [],
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "environment": "staging",
        "allowed_impact_levels": ["green", "amber", "red"],
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


def base_input(**kwargs):
    payload = {
        "target": "https://example.com",
        "normalized_target": "https://example.com",
        "source_type": "test_fixture",
        "headers": {"Server": "nginx/1.27.0", "X-Powered-By": "Express"},
        "content_type": "text/html",
        "evidence_ids": ("evidence_fetch_1",),
        "created_at_utc": "2026-01-01T00:00:00+00:00",
    }
    payload.update(kwargs)
    return TechnologyFingerprintInput(**payload)


class PassiveTechnologyFingerprintingTests(unittest.TestCase):
    def test_fingerprint_from_headers_detects_server_and_powered_by(self):
        result = fingerprint_technology(base_input())
        names = {item.name for item in result.detected_technologies}
        self.assertIn("nginx", names)
        self.assertIn("Express", names)
        self.assertIn("Node.js", names)

    def test_cloudflare_vercel_next_headers_detected(self):
        result = fingerprint_technology(
            base_input(headers={"CF-Ray": "abc", "X-Vercel-Id": "iad1::abc", "X-Nextjs-Cache": "HIT"})
        )
        names = {item.name for item in result.detected_technologies}
        self.assertIn("Cloudflare", names)
        self.assertIn("Vercel", names)
        self.assertIn("Next.js", names)

    def test_missing_security_controls_are_not_vulnerabilities(self):
        result = fingerprint_technology(base_input(headers={"Server": "nginx"}))
        self.assertIn("Content-Security-Policy", result.detected_missing_controls)
        self.assertTrue(all(item.status == "hypothesis" for item in result.risk_hypotheses))
        self.assertEqual(findings_from_fingerprint(result), [])

    def test_html_snippet_framework_markers_detected(self):
        html = """
        <html><head><meta name="generator" content="Astro 4"></head>
        <body><div id="root"></div><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>
        """
        result = fingerprint_technology(base_input(capped_html_snippet=html))
        names = {item.name for item in result.detected_technologies}
        self.assertIn("Next.js", names)
        self.assertIn("Astro 4", names)

    def test_capped_html_input_enforced(self):
        html = "<html>" + ("A" * (MAX_HTML_SNIPPET_BYTES + 100)) + "</html>"
        model = base_input(capped_html_snippet=html)
        self.assertLessEqual(len(model.capped_html_snippet.encode("utf-8")), MAX_HTML_SNIPPET_BYTES)
        result = fingerprint_technology(model)
        self.assertIn("html_snippet_truncated_to_cap", result.warnings)
        self.assertFalse(result.metadata["html_snippet_stored"])

    def test_script_and_link_asset_hints_extracted_without_fetching(self):
        html = '<script src="/_next/static/chunk.js"></script><link href="/_astro/app.css" rel="stylesheet">'
        result = fingerprint_technology(base_input(capped_html_snippet=html))
        self.assertIn("nextjs_asset_path", result.asset_hints)
        self.assertIn("astro_asset_path", result.asset_hints)

    def test_source_map_reference_is_only_hint(self):
        result = fingerprint_technology(base_input(script_src=("/static/js/app.js.map",)))
        self.assertIn("source_map_reference_hint", result.asset_hints)
        titles = {item.title for item in result.risk_hypotheses}
        self.assertIn("Source map reference supplied", titles)

    def test_admin_api_surface_hints_are_not_vulnerabilities(self):
        result = fingerprint_technology(
            base_input(
                endpoint_inventory=(
                    {"method": "GET", "path": "/admin/login", "auth_indicators": []},
                    {"method": "POST", "path": "/api/graphql", "auth_indicators": []},
                )
            )
        )
        self.assertTrue(result.admin_surface_hints)
        self.assertTrue(result.api_surface_hints)
        self.assertEqual(findings_from_fingerprint(result), [])

    def test_imported_endpoint_inventory_contributes_api_surface_hints(self):
        result = fingerprint_technology(base_input(endpoint_inventory=({"method": "GET", "path": "/api/account"},)))
        self.assertIn("path_hint:api", result.endpoint_hints)
        self.assertTrue(result.api_surface_hints)

    def test_risk_hypotheses_generated_conservatively(self):
        result = fingerprint_technology(
            base_input(
                headers={"Server": "nginx"},
                capped_html_snippet='<script src="/_next/static/app.js.map"></script>',
                endpoint_inventory=({"method": "GET", "path": "/admin/login"},),
            )
        )
        self.assertTrue(result.risk_hypotheses)
        self.assertEqual({item.status for item in result.risk_hypotheses}, {"hypothesis"})
        self.assertEqual({item.required_impact_level for item in result.risk_hypotheses}, {"green"})

    def test_fingerprints_serialize_without_raw_secrets(self):
        result = fingerprint_technology(
            base_input(headers={"Authorization": "Bearer " + SECRET_VALUE, "Set-Cookie": "sid=" + SECRET_VALUE})
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("redacted", serialized)
        self.assertTrue(result.redaction_applied)

    def test_evidence_generated_from_fingerprint_result(self):
        result = fingerprint_technology(base_input())
        evidence = evidence_from_fingerprint(result)
        self.assertEqual(evidence.source_type, EvidenceSourceType.TECHNOLOGY_FINGERPRINT.value)
        self.assertNotIn("capped_html_snippet", json.dumps(evidence.to_dict(), sort_keys=True))
        self.assertNotIn("response_body", json.dumps(evidence.to_dict(), sort_keys=True).lower())

    def test_no_confirmed_findings_from_fingerprinting(self):
        result = fingerprint_technology(base_input())
        findings = findings_from_fingerprint(result, evidence_from_fingerprint(result))
        self.assertEqual(findings, [])
        self.assertNotIn(FindingStatus.CONFIRMED.value, json.dumps(result.to_dict(), sort_keys=True))

    def test_fingerprint_from_fetch_result(self):
        fetch = SafeHttpFetchResult(
            fetch_id="fetch_1",
            target="https://example.com",
            normalized_target="https://example.com",
            method="HEAD",
            requested_by="tester",
            actor="tester",
            policy_decision={"allowed": True},
            allowed=True,
            status_code=200,
            headers={"Server": "cloudflare"},
            content_type="text/html",
        )
        result = fingerprint_from_fetch_result(fetch, evidence_ids=("evidence_fetch_1",))
        self.assertIn("Cloudflare", {item.name for item in result.detected_technologies})

    def test_cli_fingerprint_technology_returns_parseable_json(self):
        code, response = run_cli(
            ["fingerprint-technology"],
            {
                "target": "https://example.com",
                "authorization_profile": auth(),
                "metadata": {
                    "headers": {"Server": "nginx", "X-Powered-By": "Next.js"},
                    "capped_html_snippet": '<script src="/_next/static/app.js"></script>',
                    "evidence_ids": ["evidence_fetch_1"],
                },
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertIn("fingerprint", response["result"])
        self.assertEqual(response["result"]["findings"], [])

    def test_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli(["fingerprint-technology"], {"target": "https://example.com", "metadata": {}})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_adapter_dry_run_planning_does_not_call_network(self):
        from aegis_ev.adapters import AdapterPlanner, default_registry
        from aegis_ev.adapters.framework import ToolActionRequest
        from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget

        profile = AuthorizationProfile(
            owner="tester",
            allowed_domains=["example.com"],
            allowed_cidrs=[],
            valid_from=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=1),
            environment=Environment.STAGING,
            allowed_impact_levels=[ImpactLevel.GREEN],
            request_budget=PolicyBudget(max_requests=5),
        )
        plan = AdapterPlanner(default_registry()).plan(
            ToolActionRequest(
                action_id="fingerprint",
                adapter_id="technology_fingerprint",
                target="https://example.com",
                action="fingerprint_from_metadata",
                arguments={"metadata": {"headers": {"server": "nginx"}}},
                requested_impact_level=ImpactLevel.GREEN,
                actor="tester",
                authorization_profile=profile,
            )
        )
        self.assertTrue(plan.allowed)
        self.assertFalse(default_registry().get("technology_fingerprint").metadata.requires_network)

    def test_no_real_network_side_effects_or_api_keys(self):
        import aegis_ev.fingerprinting as fingerprinting

        source = inspect.getsource(fingerprinting)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("api_key", json.dumps(fingerprint_technology(base_input()).to_dict(), sort_keys=True).lower())

    def test_no_real_portfolio_url_hardcoded(self):
        import aegis_ev.fingerprinting as fingerprinting

        self.assertNotIn("portfolio.example.test", inspect.getsource(fingerprinting))


if __name__ == "__main__":
    unittest.main()
