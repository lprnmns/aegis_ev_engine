import inspect
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_ev.audit import AuditLog
from aegis_ev.evidence import FindingStatus, VerificationState
from aegis_ev.http_fetch import (
    SafeHttpFetchRequest,
    SafeHttpTransportResponse,
    analyze_headers_from_fetch_result,
    evidence_from_fetch_result,
    safe_http_fetch,
)
from aegis_ev.models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-fetch-token-1234567890"


def auth(**kwargs):
    base = {
        "owner": "customer-a/project-web",
        "allowed_domains": ["example.com"],
        "allowed_cidrs": [],
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "environment": Environment.STAGING,
        "allowed_impact_levels": [ImpactLevel.GREEN, ImpactLevel.AMBER],
        "request_budget": PolicyBudget(max_requests=10, max_requests_per_minute=30, max_concurrency=2),
        "require_approval_for_amber": False,
        "require_approval_for_production_amber": True,
    }
    base.update(kwargs)
    return AuthorizationProfile(**base)


def request(**kwargs):
    base = {
        "fetch_id": "fetch_test",
        "target": "https://example.com",
        "authorization_profile": auth(),
        "now": NOW,
    }
    base.update(kwargs)
    return SafeHttpFetchRequest(**base)


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


class SafeHttpFetchTests(unittest.TestCase):
    def test_fetch_request_defaults_to_head(self):
        self.assertEqual(request().method, "HEAD")

    def test_unsupported_scheme_denied_before_network_call(self):
        transport = CountingTransport([SafeHttpTransportResponse(status_code=200)])
        result = safe_http_fetch(request(target="ftp://example.com"), transport=transport)
        self.assertFalse(result.allowed)
        self.assertEqual(result.error, "unsupported_scheme")
        self.assertEqual(transport.calls, [])

    def test_out_of_scope_target_denied_before_network_call(self):
        transport = CountingTransport([SafeHttpTransportResponse(status_code=200)])
        result = safe_http_fetch(request(target="https://evil.test"), transport=transport)
        self.assertFalse(result.allowed)
        self.assertEqual(result.error, "target_out_of_scope")
        self.assertEqual(transport.calls, [])

    def test_valid_in_scope_target_uses_fake_transport(self):
        transport = CountingTransport(
            [SafeHttpTransportResponse(status_code=200, final_url="https://example.com", headers={"Content-Type": "text/html"}, elapsed_ms=4)]
        )
        result = safe_http_fetch(request(), transport=transport)
        self.assertTrue(result.allowed)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(transport.calls[0][0], "HEAD")

    def test_timeout_error_produces_safe_failed_result(self):
        result = safe_http_fetch(request(), transport=CountingTransport([TimeoutError("timed out")]))
        self.assertTrue(result.allowed)
        self.assertEqual(result.error, "transport_error: TimeoutError")
        self.assertTrue(result.no_body_stored)

    def test_redirect_chain_capped(self):
        transport = CountingTransport(
            [
                SafeHttpTransportResponse(status_code=302, final_url="https://example.com", headers={"Location": "/next"}),
                SafeHttpTransportResponse(status_code=302, final_url="https://example.com/next", headers={"Location": "/again"}),
            ]
        )
        result = safe_http_fetch(request(max_redirects=1), transport=transport)
        self.assertEqual(result.error, "redirect_limit_reached")
        self.assertEqual(len(result.redirect_chain), 1)
        self.assertEqual(len(transport.calls), 2)

    def test_sensitive_headers_redacted(self):
        result = safe_http_fetch(
            request(),
            transport=CountingTransport(
                [
                    SafeHttpTransportResponse(
                        status_code=200,
                        final_url="https://example.com",
                        headers={"Authorization": "Bearer " + SECRET_VALUE, "X-Api-Key": SECRET_VALUE},
                    )
                ]
            ),
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("redacted", serialized)

    def test_set_cookie_redacted(self):
        result = safe_http_fetch(
            request(),
            transport=CountingTransport([SafeHttpTransportResponse(status_code=200, headers={"Set-Cookie": "sid=" + SECRET_VALUE})]),
        )
        self.assertEqual(result.headers["Set-Cookie"], "<redacted>")

    def test_authorization_request_header_not_supported_by_model(self):
        with self.assertRaises(ValueError):
            SafeHttpFetchRequest(target="https://example.com", authorization_profile=auth(), method="POST")

    def test_no_body_stored_by_default(self):
        result = safe_http_fetch(request(method="GET"), transport=CountingTransport([SafeHttpTransportResponse(status_code=200, headers={})]))
        self.assertTrue(result.no_body_stored)
        self.assertNotIn("response_body", result.to_dict())
        self.assertNotIn("body_preview", result.to_dict())

    def test_evidence_generated_from_fetch_result(self):
        result = safe_http_fetch(request(), transport=CountingTransport([SafeHttpTransportResponse(status_code=204, headers={"Content-Length": "0"})]))
        evidence = evidence_from_fetch_result(result)
        self.assertEqual(evidence.source_type, "safe_http_fetch")
        self.assertNotIn("response_body", json.dumps(evidence.to_dict(), sort_keys=True).lower())
        self.assertNotIn("body_preview", json.dumps(evidence.to_dict(), sort_keys=True).lower())

    def test_header_analysis_integrated_from_fetched_headers(self):
        result = safe_http_fetch(
            request(),
            transport=CountingTransport([SafeHttpTransportResponse(status_code=200, headers={"Content-Type": "text/html"})]),
        )
        checks, evidence, findings = analyze_headers_from_fetch_result(result)
        self.assertTrue(checks)
        self.assertTrue(evidence)
        self.assertTrue(findings)

    def test_candidate_findings_not_confirmed_by_default(self):
        result = safe_http_fetch(
            request(),
            transport=CountingTransport([SafeHttpTransportResponse(status_code=200, headers={"Content-Type": "text/html"})]),
        )
        _checks, _evidence, findings = analyze_headers_from_fetch_result(result)
        self.assertNotIn(FindingStatus.CONFIRMED.value, {finding.status for finding in findings})
        self.assertNotIn(VerificationState.VERIFIED.value, {finding.verification_state for finding in findings})

    def test_production_approval_behavior_follows_policy(self):
        production = auth(environment=Environment.PRODUCTION, require_approval_for_amber=False)
        transport = CountingTransport([SafeHttpTransportResponse(status_code=200)])
        result = safe_http_fetch(request(authorization_profile=production, requested_impact_level=ImpactLevel.AMBER), transport=transport)
        self.assertFalse(result.allowed)
        self.assertEqual(result.error, "production_amber_requires_approval")
        self.assertEqual(transport.calls, [])

    def test_audit_event_generated_for_allowed_denied_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            safe_http_fetch(request(fetch_id="fetch_allowed"), transport=CountingTransport([SafeHttpTransportResponse(status_code=200)]), audit_log=log)
            safe_http_fetch(request(fetch_id="fetch_denied", target="https://evil.test"), transport=CountingTransport([]), audit_log=log)
            safe_http_fetch(request(fetch_id="fetch_failed"), transport=CountingTransport([TimeoutError("timed out")]), audit_log=log)
            self.assertTrue(log.verify().valid)
            raw = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertIn("http_fetch_completed", raw)
            self.assertIn("http_fetch_denied", raw)
            self.assertIn("http_fetch_failed", raw)

    def test_tests_perform_no_real_network_side_effects(self):
        import aegis_ev.http_fetch as http_fetch

        source = inspect.getsource(http_fetch)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
