import unittest

from aegis_ev.adapters.safe_headers import analyze_headers
from aegis_ev.audit import REDACTED


class SafeHeadersTests(unittest.TestCase):
    def test_analyze_headers_reports_missing_security_headers(self):
        result = analyze_headers("https://example.com", 200, {"Server": "test"})
        titles = [finding.title for finding in result.findings]
        self.assertTrue(any("Content-Security-Policy" in title for title in titles))
        self.assertEqual(result.evidence.data["status_code"], 200)

    def test_analyze_headers_accepts_present_headers_case_insensitive(self):
        result = analyze_headers(
            "https://example.com",
            200,
            {
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=31536000",
            },
        )
        self.assertEqual(result.findings, [])

    def test_analyze_headers_redacts_sensitive_legacy_evidence_values(self):
        result = analyze_headers(
            "https://example.com",
            200,
            {
                "Authorization": "Bearer not-a-real-secret-token-1234567890",
                "Set-Cookie": "sessionid=supersecretvalue1234567890; Secure; HttpOnly",
            },
        )
        serialized = str(result.evidence.data)
        self.assertNotIn("not-a-real-secret-token-1234567890", serialized)
        self.assertNotIn("supersecretvalue1234567890", serialized)
        self.assertIn(REDACTED, serialized)


if __name__ == "__main__":
    unittest.main()
