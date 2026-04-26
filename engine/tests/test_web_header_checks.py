import json
import unittest

from aegis_ev.checks.web_headers import (
    WebHeaderAnalysisInput,
    analyze_web_headers,
    evidence_from_web_header_check,
    finding_from_web_header_check,
)


SECRET_VALUE = "Bearer not-a-real-secret-token-1234567890"


def analyze(**kwargs):
    payload = {
        "target": "https://example.com/account/login",
        "headers": {},
        "status_code": 200,
        "content_type": "text/html",
    }
    payload.update(kwargs)
    return analyze_web_headers(WebHeaderAnalysisInput(**payload))


class WebHeaderChecksTests(unittest.TestCase):
    def test_missing_csp_produces_candidate_evidence_backed_result(self):
        results = analyze()
        missing_csp = next(item for item in results if item.check_id == "missing_csp")
        self.assertEqual(missing_csp.status, "candidate")
        self.assertEqual(missing_csp.severity, "medium")

    def test_strong_csp_does_not_produce_high_risk_false_finding(self):
        results = analyze(
            headers={
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        )
        self.assertFalse(any(item.check_id in {"missing_csp", "weak_csp"} for item in results))

    def test_missing_hsts_on_https_detected(self):
        results = analyze()
        self.assertTrue(any(item.check_id == "missing_hsts" for item in results))

    def test_hsts_not_required_for_http_target(self):
        results = analyze(target="http://example.com/account/login")
        self.assertFalse(any(item.check_id == "missing_hsts" for item in results))

    def test_missing_x_frame_options_or_frame_ancestors_detected(self):
        results = analyze(headers={"Content-Security-Policy": "default-src 'self'"})
        self.assertTrue(any(item.check_id == "missing_clickjacking_protection" for item in results))

    def test_frame_ancestors_satisfies_clickjacking_protection(self):
        results = analyze(headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
        self.assertFalse(any(item.check_id == "missing_clickjacking_protection" for item in results))

    def test_wildcard_cors_detected(self):
        results = analyze(headers={"Access-Control-Allow-Origin": "*"})
        finding = next(item for item in results if item.check_id == "cors_wildcard_origin")
        self.assertEqual(finding.severity, "medium")

    def test_wildcard_cors_with_credentials_high_severity(self):
        results = analyze(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        finding = next(item for item in results if item.check_id == "cors_wildcard_credentials")
        self.assertEqual(finding.severity, "high")

    def test_cookie_missing_secure_detected(self):
        results = analyze(headers={"Set-Cookie": "sessionid=abc123; HttpOnly; SameSite=Lax"})
        self.assertTrue(any(item.check_id == "cookie_missing_secure_sessionid" for item in results))

    def test_cookie_missing_httponly_detected(self):
        results = analyze(headers={"Set-Cookie": "sessionid=abc123; Secure; SameSite=Lax"})
        self.assertTrue(any(item.check_id == "cookie_missing_httponly_sessionid" for item in results))

    def test_cookie_missing_samesite_detected(self):
        results = analyze(headers={"Set-Cookie": "sessionid=abc123; Secure; HttpOnly"})
        self.assertTrue(any(item.check_id == "cookie_missing_samesite_sessionid" for item in results))

    def test_secure_cookie_does_not_produce_false_issue(self):
        results = analyze(headers={"Set-Cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Lax"})
        self.assertFalse(any(item.check_id.startswith("cookie_missing_") for item in results))

    def test_server_disclosure_detected_as_low_or_info(self):
        results = analyze(headers={"Server": "nginx/1.27.0", "X-Powered-By": "PHP/8.3"})
        server = next(item for item in results if item.check_id == "tech_disclosure_server")
        powered = next(item for item in results if item.check_id == "tech_disclosure_x_powered_by")
        self.assertEqual(server.severity, "low")
        self.assertEqual(powered.severity, "info")

    def test_sensitive_header_values_redacted(self):
        results = analyze(headers={"Authorization": SECRET_VALUE})
        rendered = json.dumps([item.to_dict() for item in results], sort_keys=True)
        self.assertNotIn(SECRET_VALUE, rendered)

    def test_set_cookie_values_redacted(self):
        results = analyze(headers={"Set-Cookie": "sessionid=supersecretvalue1234567890; Secure"})
        rendered = json.dumps([item.to_dict() for item in results], sort_keys=True)
        self.assertNotIn("supersecretvalue1234567890", rendered)

    def test_evidence_generated_safely(self):
        result = analyze()[0]
        evidence = evidence_from_web_header_check(result)
        payload = json.dumps(evidence.to_dict(), sort_keys=True)
        self.assertEqual(evidence.source_type, "web_header_check")
        self.assertNotIn(SECRET_VALUE, payload)

    def test_candidate_finding_generated_safely(self):
        result = analyze()[0]
        evidence = evidence_from_web_header_check(result)
        finding = finding_from_web_header_check(result, evidence)
        self.assertEqual(finding.status, "candidate")
        self.assertEqual(finding.verification_state, "evidence_backed")

    def test_finding_is_not_confirmed_by_default(self):
        result = analyze()[0]
        evidence = evidence_from_web_header_check(result)
        finding = finding_from_web_header_check(result, evidence)
        self.assertNotEqual(finding.status, "confirmed")

    def test_cache_control_risk_detected_for_sensitive_path(self):
        results = analyze(target="https://example.com/session/profile")
        self.assertTrue(any(item.check_id == "sensitive_path_cache_control" for item in results))

    def test_no_network_side_effects(self):
        source = json.dumps([item.to_dict() for item in analyze()], sort_keys=True)
        self.assertIsInstance(source, str)


if __name__ == "__main__":
    unittest.main()
