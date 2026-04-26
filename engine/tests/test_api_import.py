import inspect
import json
import unittest
from datetime import datetime, timezone

from aegis_ev.evidence import FindingRecord
from aegis_ev.imports import evidence_from_import_result, import_har, import_openapi, import_postman


SECRET_VALUE = "not-a-real-import-token-1234567890"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def openapi_fixture():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Example API", "version": "1.0.0"},
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": SECRET_VALUE}
            }
        },
        "security": [{"BearerAuth": []}],
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "summary": "List users",
                    "tags": ["users"],
                    "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/admin/payments": {
                "post": {
                    "summary": "Create payment",
                    "security": [],
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"201": {"description": "Created"}},
                }
            },
        },
    }


def postman_fixture():
    return {
        "info": {"name": "Example Postman"},
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": SECRET_VALUE}]},
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "name": "List users",
                        "event": [{"listen": "prerequest", "script": {"exec": ["throw new Error('must not run')"]}}],
                        "request": {
                            "method": "GET",
                            "url": {"raw": f"https://example.com/users?token={SECRET_VALUE}"},
                            "header": [{"key": "Authorization", "value": "Bearer " + SECRET_VALUE}],
                        },
                    }
                ],
            }
        ],
    }


def har_fixture():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": f"https://example.com/account?session={SECRET_VALUE}",
                        "headers": [{"name": "Authorization", "value": "Bearer " + SECRET_VALUE}],
                        "cookies": [{"name": "sessionid", "value": SECRET_VALUE}],
                        "queryString": [{"name": "session", "value": SECRET_VALUE}],
                        "postData": {"mimeType": "application/json", "text": "{\"password\":\"secret\"}"},
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": f"https://example.com/account?session={SECRET_VALUE}",
                        "headers": [],
                    }
                },
            ]
        }
    }


class ApiImportTests(unittest.TestCase):
    def test_openapi_json_import_extracts_endpoints(self):
        result = import_openapi(openapi_fixture(), now=NOW)
        self.assertEqual(result.endpoint_count, 2)
        self.assertEqual(sorted(item.method for item in result.endpoints), ["GET", "POST"])
        self.assertTrue(any(item.operation_id == "listUsers" for item in result.endpoints))

    def test_openapi_invalid_input_fails_safely(self):
        result = import_openapi({"openapi": "3.0.3"}, now=NOW)
        self.assertEqual(result.endpoint_count, 0)
        self.assertTrue(result.errors)

    def test_openapi_remote_refs_are_not_fetched(self):
        payload = openapi_fixture()
        payload["paths"]["/users"]["get"]["responses"]["200"]["$ref"] = "https://example.com/remote-schema.json"
        result = import_openapi(payload, now=NOW)
        self.assertIn("Remote $ref ignored; no network fetch was performed", result.warnings)

    def test_openapi_security_schemes_summarized_without_secrets(self):
        result = import_openapi(openapi_fixture(), now=NOW)
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertIn("BearerAuth", serialized)
        self.assertNotIn(SECRET_VALUE, serialized)

    def test_postman_collection_import_extracts_nested_endpoints(self):
        result = import_postman(postman_fixture(), now=NOW)
        self.assertEqual(result.endpoint_count, 1)
        self.assertEqual(result.endpoints[0].path, "/users")
        self.assertIn("bearer", result.endpoints[0].auth_indicators)

    def test_postman_auth_header_secrets_redacted(self):
        result = import_postman(postman_fixture(), now=NOW)
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("Authorization", serialized)

    def test_postman_scripts_are_not_executed_or_evaluated(self):
        result = import_postman(postman_fixture(), now=NOW)
        self.assertTrue(any("scripts were observed and ignored" in warning for warning in result.warnings))
        self.assertNotIn("must not run", json.dumps(result.to_dict(), sort_keys=True))

    def test_har_import_extracts_endpoints(self):
        result = import_har(har_fixture(), now=NOW)
        self.assertEqual(result.endpoint_count, 1)
        self.assertEqual(result.endpoints[0].method, "GET")
        self.assertEqual(result.endpoints[0].host, "example.com")

    def test_har_cookies_and_auth_headers_redacted(self):
        result = import_har(har_fixture(), now=NOW)
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("sessionid", serialized)
        self.assertIn("Authorization", serialized)

    def test_har_request_bodies_not_dumped(self):
        result = import_har(har_fixture(), now=NOW)
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("password", serialized)
        self.assertEqual(result.endpoints[0].request_body_summary, "present redacted")

    def test_duplicate_har_endpoints_deduplicated(self):
        result = import_har(har_fixture(), now=NOW)
        self.assertEqual(result.endpoint_count, 1)

    def test_query_secret_values_redacted(self):
        result = import_har(har_fixture(), now=NOW)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.normalized_url, "https://example.com/account")
        self.assertNotIn(SECRET_VALUE, json.dumps(endpoint.to_dict(), sort_keys=True))

    def test_endpoint_ids_deterministic(self):
        first = import_openapi(openapi_fixture(), now=NOW)
        second = import_openapi(openapi_fixture(), now=NOW)
        self.assertEqual([item.endpoint_id for item in first.endpoints], [item.endpoint_id for item in second.endpoints])
        self.assertEqual(first.import_id, second.import_id)

    def test_evidence_generated_safely_from_import_result(self):
        result = import_har(har_fixture(), now=NOW)
        evidence = evidence_from_import_result(result)
        serialized = json.dumps(evidence.to_dict(), sort_keys=True)
        self.assertEqual(evidence.source_type, "api_import")
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("Imported 1 endpoint", evidence.summary)

    def test_imports_do_not_create_confirmed_findings(self):
        result = import_openapi(openapi_fixture(), now=NOW)
        self.assertNotIn("findings", result.to_dict())
        self.assertTrue(any(endpoint.risk_hints for endpoint in result.endpoints))
        finding = FindingRecord(
            title="Import risk hint",
            description="Risk hints are not confirmed findings",
            severity="info",
            confidence="low",
            status="draft",
        )
        self.assertNotEqual(finding.status, "confirmed")

    def test_no_network_side_effects(self):
        import aegis_ev.imports.api_import as api_import

        source = inspect.getsource(api_import)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
