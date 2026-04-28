import io
import json
import unittest
import unittest.mock
from contextlib import redirect_stdout

from aegis_ev.bridge import allowed_bridge_commands, main, run_bridge_command


def run_cli(command, payload=None):
    stdin = "" if payload is None else json.dumps(payload)
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        with unittest.mock.patch("sys.stdin", io.StringIO(stdin)):
            code = main(["--command", command])
    return code, json.loads(stdout.getvalue())


class BridgeTests(unittest.TestCase):
    def test_allowed_commands_are_no_network_subset(self):
        commands = set(allowed_bridge_commands())
        self.assertIn("engine_health", commands)
        self.assertIn("list_tool_capabilities", commands)
        self.assertNotIn("-".join(("run", "portfolio", "demo")), commands)
        self.assertNotIn("-".join(("run", "portfolio", "operator", "pipeline")), commands)
        self.assertNotIn("-".join(("fetch", "http", "metadata")), commands)

    def test_engine_health_returns_safe_flags(self):
        result = run_bridge_command("engine_health").to_dict()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["executed_live_network"])
        self.assertFalse(result["executed_external_tool"])
        self.assertFalse(result["data"]["live_portfolio_execution_enabled"])

    def test_unknown_command_rejected(self):
        result = run_bridge_command("-".join(("fetch", "http", "metadata"))).to_dict()
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["errors"][0]["code"], "unsupported_bridge_command")

    def test_local_demo_flow_returns_ui_summaries(self):
        result = run_bridge_command("run_local_demo_flow_no_network").to_dict()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["executed_live_network"])
        self.assertFalse(result["executed_external_tool"])
        demo = result["data"]["demo"]
        self.assertTrue(demo["no_network"])
        self.assertGreater(demo["evidence_count"], 0)
        self.assertGreater(demo["finding_count"], 0)
        self.assertGreater(len(demo["pipeline_stage_summaries"]), 0)
        self.assertGreater(len(demo["evidence_summaries"]), 0)
        self.assertGreater(len(demo["finding_summaries"]), 0)
        self.assertGreater(len(demo["report_summaries"]), 0)
        self.assertFalse(demo["safety_flags"]["executed_live_network"])
        self.assertFalse(demo["safety_flags"]["executed_external_tool"])
        self.assertEqual(demo["finding_summaries"][0]["status"], "candidate")
        self.assertEqual(demo["finding_summaries"][0]["verification"], "evidence_backed")

    def test_payload_containing_real_portfolio_domain_rejected(self):
        real_domain = ".".join(("alperenmanas", "app"))
        result = run_bridge_command("engine_health", {"target": f"https://{real_domain}"}).to_dict()
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["errors"][0]["code"], "real_portfolio_url_denied")

    def test_payload_containing_secret_key_rejected(self):
        result = run_bridge_command("engine_health", {"secret": "redacted"}).to_dict()
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["errors"][0]["code"], "forbidden_payload_key")

    def test_payload_containing_arbitrary_argv_rejected(self):
        result = run_bridge_command("engine_health", {"argv": ["python3", "-m", "anything"]}).to_dict()
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["errors"][0]["code"], "arbitrary_execution_shape_denied")

    def test_list_tool_capabilities_runs_metadata_only(self):
        result = run_bridge_command("list_tool_capabilities").to_dict()
        self.assertEqual(result["status"], "ok")
        self.assertGreater(result["data"]["tool_count"], 0)
        self.assertFalse(result["executed_live_network"])
        self.assertFalse(result["executed_external_tool"])

    def test_build_ai_planner_packet_runs_without_model_call(self):
        result = run_bridge_command("build_ai_planner_packet").to_dict()
        self.assertEqual(result["status"], "ok")
        self.assertIn("packet", result["data"])
        self.assertFalse(result["executed_live_network"])

    def test_fixture_graph_and_intel_commands_run(self):
        graph = run_bridge_command("build_attack_surface_graph_from_fixture").to_dict()
        intel = run_bridge_command("map_vulnerability_intelligence_from_fixture").to_dict()
        self.assertEqual(graph["status"], "ok")
        self.assertEqual(intel["status"], "ok")
        self.assertFalse(graph["executed_live_network"])
        self.assertFalse(intel["executed_external_tool"])

    def test_bridge_cli_returns_parseable_json(self):
        code, response = run_cli("engine_health", {})
        self.assertEqual(code, 0)
        self.assertEqual(response["status"], "ok")

    def test_bridge_cli_invalid_input_returns_structured_error(self):
        code, response = run_cli("engine_health", {"password": "redacted"})
        self.assertEqual(code, 1)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["errors"][0]["code"], "forbidden_payload_key")

    def test_bridge_output_contains_no_raw_secrets(self):
        result = run_bridge_command("list_model_providers").to_json().lower()
        self.assertNotIn("sk-", result)
        self.assertNotIn("bearer ", result)


if __name__ == "__main__":
    unittest.main()
