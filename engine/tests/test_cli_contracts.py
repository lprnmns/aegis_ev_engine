import inspect
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aegis_ev.audit import AuditLog
from aegis_ev.main import main


NOW = datetime.now(timezone.utc)
SECRET_VALUE = "not-a-real-cli-token-1234567890"


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


class EngineCliContractTests(unittest.TestCase):
    def test_cli_json_output_parseable_and_shape_stable(self):
        code, response = run_cli(
            ["validate-policy"],
            {
                "target": "https://example.com",
                "impact": "green",
                "authorization_profile": auth(),
            },
        )
        self.assertEqual(code, 0)
        self.assertEqual(set(response), {"ok", "command", "result", "error", "warnings", "metadata"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["command"], "validate-policy")

    def test_invalid_json_returns_structured_error_and_nonzero(self):
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("{not-json}")), redirect_stdout(stdout):
            code = main(["validate-policy"])
        response = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_json")
        self.assertNotIn("Traceback", stdout.getvalue())

    def test_missing_input_returns_structured_error(self):
        code, response = run_cli(["validate-policy"])
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "missing_input")

    def test_policy_validation_allows_valid_scoped_target(self):
        code, response = run_cli(
            ["validate-policy"],
            {
                "target": "https://example.com/path?token=" + SECRET_VALUE,
                "impact": "green",
                "authorization_profile": auth(),
            },
        )
        decision = response["result"]["policy_decision"]
        self.assertEqual(code, 0)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["decision_code"], "allowed")
        self.assertEqual(decision["normalized_target"], "https://example.com/path")
        self.assertNotIn(SECRET_VALUE, json.dumps(response, sort_keys=True))

    def test_policy_validation_denies_out_of_scope_target(self):
        code, response = run_cli(
            ["validate-policy"],
            {"target": "https://evil.test", "impact": "green", "authorization_profile": auth()},
        )
        decision = response["result"]["policy_decision"]
        self.assertEqual(code, 0)
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["decision_code"], "target_out_of_scope")

    def test_adapter_plan_returns_dry_run_plan(self):
        code, response = run_cli(
            ["plan-adapter"],
            {
                "action_id": "action_1",
                "adapter_id": "echo_plan",
                "target": "https://example.com",
                "action": "plan",
                "arguments": {"message": "safe"},
                "requested_impact_level": "green",
                "actor": "tester",
                "authorization_profile": auth(),
            },
        )
        plan = response["result"]["plan"]
        self.assertEqual(code, 0)
        self.assertTrue(plan["allowed"])
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["command_preview"], ["aegis-ev-adapter", "echo_plan", "plan", "--dry-run"])

    def test_adapter_plan_denies_unknown_adapter(self):
        code, response = run_cli(
            ["plan-adapter"],
            {
                "action_id": "action_1",
                "adapter_id": "missing",
                "target": "https://example.com",
                "action": "plan",
                "arguments": {},
                "requested_impact_level": "green",
                "actor": "tester",
                "authorization_profile": auth(),
            },
        )
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "unknown_adapter")

    def test_analyze_web_headers_returns_parseable_json(self):
        code, response = run_cli(
            ["analyze-web-headers"],
            {
                "target": "https://example.com/account/login",
                "headers": {"Server": "nginx/1.27.0", "Set-Cookie": "sessionid=abc123; Secure"},
                "authorization_profile": auth(),
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["command"], "analyze-web-headers")
        self.assertIn("checks", response["result"])
        self.assertIn("evidence", response["result"])
        self.assertIn("findings", response["result"])

    def test_analyze_web_headers_invalid_input_returns_structured_error(self):
        code, response = run_cli(
            ["analyze-web-headers"],
            {
                "target": "https://example.com/account/login",
                "headers": "not-an-object",
                "authorization_profile": auth(),
            },
        )
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_analyze_web_headers_does_not_leak_secrets(self):
        code, response = run_cli(
            ["analyze-web-headers"],
            {
                "target": "https://example.com/account/login",
                "headers": {"Authorization": SECRET_VALUE, "Set-Cookie": "sessionid=supersecretvalue1234567890; Secure"},
                "authorization_profile": auth(),
            },
        )
        self.assertEqual(code, 0)
        rendered = json.dumps(response, sort_keys=True)
        self.assertNotIn(SECRET_VALUE, rendered)
        self.assertNotIn("supersecretvalue1234567890", rendered)

    def test_cli_import_openapi_returns_parseable_json(self):
        code, response = run_cli(
            ["import-openapi"],
            {
                "source_name": "Example API",
                "data": {
                    "openapi": "3.0.3",
                    "info": {"title": "Example API", "version": "1.0.0"},
                    "paths": {"/users": {"get": {"summary": "List users", "responses": {"200": {"description": "OK"}}}}},
                },
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["endpoint_count"], 1)

    def test_cli_import_postman_returns_parseable_json(self):
        code, response = run_cli(
            ["import-postman"],
            {
                "data": {
                    "info": {"name": "Example Postman"},
                    "item": [{"name": "Users", "request": {"method": "GET", "url": {"raw": "https://example.com/users"}}}],
                },
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["endpoint_count"], 1)

    def test_cli_import_har_returns_parseable_json(self):
        code, response = run_cli(
            ["import-har"],
            {
                "data": {
                    "log": {
                        "entries": [
                            {"request": {"method": "GET", "url": "https://example.com/account?token=" + SECRET_VALUE}}
                        ]
                    }
                },
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["endpoint_count"], 1)
        self.assertNotIn(SECRET_VALUE, json.dumps(response, sort_keys=True))

    def test_cli_import_invalid_input_returns_structured_error(self):
        code, response = run_cli(["import-openapi"], {"data": {"openapi": "3.0.3"}})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_import")

    def test_cli_create_project_returns_parseable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = str(Path(tmp) / "workspace.json")
            code, response = run_cli(
                ["create-project"],
                {
                    "workspace_store": store_path,
                    "project": {
                        "project_id": "project_cli",
                        "name": "Portfolio Placeholder",
                        "scope": {
                            "scope_id": "scope_cli",
                            "allowlist_domains": ["portfolio.example.test"],
                            "allowed_schemes": ["https"],
                            "valid_from": "2026-01-01T00:00:00+00:00",
                            "valid_until": "2026-12-31T00:00:00+00:00",
                        },
                    },
                },
            )
            self.assertEqual(code, 0)
            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["project"]["project_id"], "project_cli")

    def test_cli_add_target_returns_parseable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = str(Path(tmp) / "workspace.json")
            run_cli(
                ["create-project"],
                {
                    "workspace_store": store_path,
                    "project": {
                        "project_id": "project_cli",
                        "name": "Portfolio Placeholder",
                        "scope": {
                            "scope_id": "scope_cli",
                            "allowlist_domains": ["portfolio.example.test"],
                            "allowed_schemes": ["https"],
                            "valid_from": "2026-01-01T00:00:00+00:00",
                            "valid_until": "2026-12-31T00:00:00+00:00",
                        },
                    },
                },
            )
            code, response = run_cli(
                ["add-target"],
                {
                    "workspace_store": store_path,
                    "project_id": "project_cli",
                    "target": {
                        "target_type": "url",
                        "value": "https://portfolio.example.test?token=" + SECRET_VALUE,
                    },
                },
            )
            self.assertEqual(code, 0)
            self.assertTrue(response["ok"])
            target = response["result"]["target"]
            self.assertTrue(target["in_scope"])
            self.assertEqual(target["normalized_value"], "https://portfolio.example.test")
            self.assertNotIn(SECRET_VALUE, json.dumps(response, sort_keys=True))

    def test_cli_project_invalid_input_returns_structured_error(self):
        code, response = run_cli(["create-project"], {"project": {"project_id": "project_bad", "status": "done"}})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_cli_run_demo_flow_returns_parseable_json(self):
        code, response = run_cli(["run-demo-flow"], {"fixture_dir": "../fixtures/demo", "no_network": True})
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        demo = response["result"]["demo"]
        self.assertTrue(demo["no_network"])
        self.assertGreater(demo["evidence_count"], 0)
        self.assertIn("markdown", demo["reports"])

    def test_cli_run_demo_flow_invalid_input_returns_structured_error(self):
        code, response = run_cli(["run-demo-flow"], {"no_network": False})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_report_render_returns_deterministic_markdown(self):
        payload = report_payload(format="markdown")
        first = run_cli(["render-report"], payload)
        second = run_cli(["render-report"], payload)
        self.assertEqual(first, second)
        self.assertIn("# Example Project Security Validation Report", first[1]["result"]["content"])

    def test_report_render_returns_deterministic_json(self):
        payload = report_payload(format="json")
        first = run_cli(["render-report"], payload)
        second = run_cli(["render-report"], payload)
        self.assertEqual(first, second)
        parsed = json.loads(first[1]["result"]["content"])
        self.assertEqual(parsed["schema_version"], "report.v1")

    def test_report_render_does_not_leak_secrets(self):
        code, response = run_cli(["render-report"], report_payload(format="markdown", secret=True))
        rendered = json.dumps(response, sort_keys=True)
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET_VALUE, rendered)
        self.assertIn("redacted", rendered)

    def test_audit_verify_handles_empty_valid_and_tampered_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            code, response = run_cli(["verify-audit"], {"audit_log": str(empty)})
            self.assertEqual(code, 0)
            self.assertTrue(response["result"]["valid"])
            log_path = Path(tmp) / "audit.jsonl"
            log = AuditLog(log_path)
            log.append("system", "policy.allow", "https://example.com", {"reason": "test"})
            code, response = run_cli(["verify-audit"], {"audit_log": str(log_path)})
            self.assertEqual(code, 0)
            self.assertTrue(response["result"]["valid"])
            event = json.loads(log_path.read_text(encoding="utf-8"))
            event["action"] = "tampered"
            log_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            code, response = run_cli(["verify-audit"], {"audit_log": str(log_path)})
            self.assertEqual(code, 0)
            self.assertFalse(response["result"]["valid"])

    def test_machine_commands_avoid_raw_stack_traces_by_default(self):
        code, response = run_cli(["validate-policy"], {"target": "https://example.com"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertNotIn("Traceback", json.dumps(response))

    def test_no_api_key_required(self):
        code, response = run_cli(
            ["validate-policy"],
            {"target": "https://example.com", "impact": "green", "authorization_profile": auth()},
        )
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])

    def test_no_shell_true_or_network_path_added_to_contract_cli(self):
        import aegis_ev.contracts as contracts
        import aegis_ev.main as cli_main

        source = inspect.getsource(contracts) + inspect.getsource(cli_main)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("import requests", source)

    def test_input_file_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(
                json.dumps({"target": "https://example.com", "impact": "green", "authorization_profile": auth()}),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["validate-policy", "--input-file", str(path)])
            response = json.loads(stdout.getvalue())
            self.assertEqual(code, 0)
            self.assertTrue(response["ok"])

    def test_cli_create_list_approve_reject_consume_commands_return_stable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = str(Path(tmp) / "approvals.json")
            create_payload = {
                "approval_store": store_path,
                "approval": {
                    "approval_id": "approval_1",
                    "created_at_utc": "2026-01-01T00:00:00+00:00",
                    "requested_by": "builder",
                    "requested_actor_type": "human",
                    "action_type": "plan",
                    "target": "https://example.com/path",
                    "normalized_target": "https://example.com/path",
                    "impact_level": "red",
                    "reason": "Red action",
                    "policy_decision_code": "red_requires_approval",
                    "adapter_id": "echo_plan",
                    "adapter_action": "plan",
                    "required_approval_scope": {
                        "target": "https://example.com/path",
                        "normalized_target": "https://example.com/path",
                        "action_type": "plan",
                        "impact_level": "red",
                        "adapter_id": "echo_plan",
                        "adapter_action": "plan",
                    },
                },
            }
            code, response = run_cli(["create-approval"], create_payload)
            self.assertEqual(code, 0)
            self.assertTrue(response["ok"])
            code, response = run_cli(["list-approvals"], {"approval_store": store_path})
            self.assertEqual(code, 0)
            self.assertEqual(len(response["result"]["approvals"]), 1)
            code, response = run_cli(
                ["approve-action"],
                {"approval_store": store_path, "approval_id": "approval_1", "approved_by": "reviewer", "actor_type": "human"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(response["result"]["approval"]["status"], "approved")
            code, response = run_cli(
                ["consume-approval"],
                {"approval_store": store_path, "approval_id": "approval_1", "consumer": "adapter"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(response["result"]["approval"]["status"], "consumed")

            reject_store = str(Path(tmp) / "approvals_reject.json")
            code, response = run_cli(["create-approval"], create_payload | {"approval_store": reject_store})
            self.assertEqual(code, 0)
            code, response = run_cli(
                ["reject-action"],
                {"approval_store": reject_store, "approval_id": "approval_1", "rejected_by": "reviewer", "actor_type": "human"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(response["result"]["approval"]["status"], "rejected")

    def test_invalid_cli_input_for_approval_returns_structured_error(self):
        code, response = run_cli(["approve-action"], {"approval_store": "/tmp/none"})
        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_matching_approved_request_can_allow_red_policy_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = str(Path(tmp) / "approvals.json")
            code, response = run_cli(
                ["validate-policy"],
                {
                    "target": "https://example.com/path",
                    "impact": "red",
                    "action_type": "plan",
                    "adapter": "echo_plan",
                    "authorization_profile": auth(),
                    "approval_store": store_path,
                    "create_approval_if_required": True,
                    "approval_request": {"requested_by": "builder", "requested_actor_type": "human"},
                },
            )
            self.assertEqual(code, 0)
            self.assertFalse(response["result"]["policy_decision"]["allowed"])
            approval_id = response["result"]["approval_request"]["approval_id"]
            code, response = run_cli(
                ["approve-action"],
                {"approval_store": store_path, "approval_id": approval_id, "approved_by": "reviewer", "actor_type": "human"},
            )
            self.assertEqual(code, 0)
            code, response = run_cli(
                ["validate-policy"],
                {
                    "target": "https://example.com/path",
                    "impact": "red",
                    "action_type": "plan",
                    "adapter": "echo_plan",
                    "authorization_profile": auth(),
                    "approval_store": store_path,
                    "approval_id": approval_id,
                },
            )
            self.assertEqual(code, 0)
            self.assertTrue(response["result"]["policy_decision"]["allowed"])


def report_payload(*, format="json", secret=False):
    summary = "Bearer " + SECRET_VALUE if secret else "One candidate finding."
    return {
        "format": format,
        "report": {
            "report_id": "report_1",
            "created_at_utc": "2026-01-01T00:00:00+00:00",
            "project_name": "Example Project",
            "environment": "staging",
            "scope_summary": "example.com only",
            "authorization_summary": "authorized",
            "executive_summary": summary,
            "methodology_summary": "deterministic",
            "limitations": ["no scanners"],
        },
        "evidence": [
            {
                "evidence_id": "evidence_1",
                "created_at_utc": "2026-01-01T00:00:00+00:00",
                "evidence_type": "manual_note",
                "source_type": "human",
                "source_id": "manual_1",
                "target": "https://example.com/path",
                "normalized_target": "https://example.com/path",
                "title": "Manual note",
                "summary": "Safe reference",
                "structured_data": {"token": SECRET_VALUE} if secret else {},
                "tags": ["manual"],
                "confidence": "medium",
            }
        ],
        "findings": [
            {
                "finding_id": "finding_1",
                "created_at_utc": "2026-01-01T00:00:00+00:00",
                "title": "Candidate finding",
                "description": "Needs review",
                "severity": "low",
                "confidence": "medium",
                "status": "candidate",
                "target": "https://example.com/path",
                "normalized_target": "https://example.com/path",
                "category": "demo",
                "evidence_ids": ["evidence_1"],
                "remediation": "Review.",
                "verification_state": "evidence_backed",
            }
        ],
        "audit_verification": {"valid": True, "event_count": 0, "last_hash": "GENESIS", "errors": []},
    }


if __name__ == "__main__":
    unittest.main()
