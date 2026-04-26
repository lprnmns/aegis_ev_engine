import unittest

from aegis_ev.adapters.safe_headers import analyze_headers


class SafeHeadersTests(unittest.TestCase):
    def test_analyze_headers_reports_missing_security_headers(self):
        result = analyze_headers("https://example.com", 200, {"Server": "test"})
        titles = [finding.title for finding in result.findings]
        self.assertTrue(any("content-security-policy" in title for title in titles))
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


if __name__ == "__main__":
    unittest.main()
