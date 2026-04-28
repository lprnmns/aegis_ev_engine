from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .attack_surface import build_attack_surface_graph
from .audit import canonical_json, redact_value
from .contracts import run_contract_command


FORBIDDEN_COMMANDS = {
    "run-portfolio-demo",
    "run-portfolio-operator-pipeline",
    "fetch-http-metadata",
    "fetch-and-analyze-headers",
    "check-tool-availability",
    "plan-tool-action",
    "execute-mock-model-request",
    "route-model-request",
}
FORBIDDEN_KEYS = {"api_key", "authorization", "cookie", "set-cookie", "bearer", "password", "secret"}
TOKEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
REAL_PORTFOLIO_DOMAIN = ".".join(("alperenmanas", "app"))
PLACEHOLDER_TARGET = "https://portfolio.example.test"
ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class BridgeCommandResult:
    command_name: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    redaction_applied: bool = True
    executed_live_network: bool = False
    executed_external_tool: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_name": self.command_name,
            "status": self.status,
            "data": redact_value(self.data),
            "warnings": list(self.warnings),
            "errors": [
                {
                    "code": str(error.get("code", "bridge_error")),
                    "message": str(error.get("message", "Bridge error")),
                    **({"details": redact_value(error["details"])} if isinstance(error, dict) and "details" in error else {}),
                }
                for error in self.errors
                if isinstance(error, dict)
            ],
            "redaction_applied": self.redaction_applied,
            "executed_live_network": self.executed_live_network,
            "executed_external_tool": self.executed_external_tool,
            "metadata": redact_value(self.metadata),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def allowed_bridge_commands() -> tuple[str, ...]:
    return tuple(BRIDGE_COMMANDS)


def run_bridge_command(command_name: str, payload: dict[str, Any] | None = None) -> BridgeCommandResult:
    payload = payload or {}
    if command_name not in BRIDGE_COMMANDS:
        return _denied(command_name, "unsupported_bridge_command", "Bridge command is not allowlisted")
    validation_error = _validate_payload(payload)
    if validation_error:
        return _denied(command_name, validation_error[0], validation_error[1])
    try:
        result = BRIDGE_COMMANDS[command_name](payload)
    except Exception as exc:  # pragma: no cover - defensive bridge boundary.
        return _denied(command_name, "bridge_command_failed", "Bridge command failed", details={"type": type(exc).__name__})
    return result


def _engine_health(_: dict[str, Any]) -> BridgeCommandResult:
    return _success(
        "engine_health",
        {
            "engine": "aegis_ev",
            "bridge_mode": "allowlisted_no_network_stub",
            "safe_mode_default": True,
            "live_portfolio_execution_enabled": False,
            "external_tool_execution_enabled": False,
            "model_provider_execution_enabled": False,
            "allowed_commands": list(allowed_bridge_commands()),
        },
    )


def _run_local_demo_flow_no_network(_: dict[str, Any]) -> BridgeCommandResult:
    response = run_contract_command("run-demo-flow", {"no_network": True, "include_report_contents": False})
    return _from_contract("run_local_demo_flow_no_network", response.to_dict())


def _build_ai_planner_packet(payload: dict[str, Any]) -> BridgeCommandResult:
    response = run_contract_command("build-ai-planner-packet", _planner_context(payload))
    return _from_contract("build_ai_planner_packet", response.to_dict())


def _list_model_providers(_: dict[str, Any]) -> BridgeCommandResult:
    response = run_contract_command("list-model-providers", {})
    return _from_contract("list_model_providers", response.to_dict())


def _list_tool_capabilities(_: dict[str, Any]) -> BridgeCommandResult:
    response = run_contract_command("list-tool-capabilities", {"tier": "green"})
    return _from_contract("list_tool_capabilities", response.to_dict())


def _build_attack_surface_graph_from_fixture(_: dict[str, Any]) -> BridgeCommandResult:
    graph_input = _demo_attack_surface_fixture()
    response = run_contract_command(
        "build-attack-surface-graph",
        {
            "target": PLACEHOLDER_TARGET,
            "authorization_profile": _authorization_profile(),
            "graph_input": graph_input,
            "dry_run": True,
        },
    )
    return _from_contract("build_attack_surface_graph_from_fixture", response.to_dict())


def _map_vulnerability_intelligence_from_fixture(_: dict[str, Any]) -> BridgeCommandResult:
    graph_input = _demo_attack_surface_fixture()
    graph = build_attack_surface_graph(graph_input).to_dict()
    knowledge_records: list[dict[str, Any]] = []
    for path in (
        ROOT / "fixtures" / "knowledge" / "owasp_web_baseline.json",
        ROOT / "fixtures" / "knowledge" / "cwe_baseline.json",
        ROOT / "fixtures" / "knowledge" / "vuln_intel_sample.json",
    ):
        knowledge_records.extend(json.loads(path.read_text(encoding="utf-8"))["records"])
    response = run_contract_command(
        "map-vulnerability-intelligence",
        {
            "target": PLACEHOLDER_TARGET,
            "authorization_profile": _authorization_profile(),
            "mapping_input": {
                "created_at_utc": "2026-01-01T00:00:00+00:00",
                "environment": "staging",
                "attack_surface_graph": graph,
                "technology_fingerprint": graph_input["technology_fingerprint"],
                "knowledge_records": knowledge_records,
                "evidence": graph_input["evidence"],
            },
            "dry_run": True,
        },
    )
    return _from_contract("map_vulnerability_intelligence_from_fixture", response.to_dict())


BRIDGE_COMMANDS: dict[str, Callable[[dict[str, Any]], BridgeCommandResult]] = {
    "engine_health": _engine_health,
    "run_local_demo_flow_no_network": _run_local_demo_flow_no_network,
    "build_ai_planner_packet": _build_ai_planner_packet,
    "list_model_providers": _list_model_providers,
    "list_tool_capabilities": _list_tool_capabilities,
    "build_attack_surface_graph_from_fixture": _build_attack_surface_graph_from_fixture,
    "map_vulnerability_intelligence_from_fixture": _map_vulnerability_intelligence_from_fixture,
}


def _success(command_name: str, data: dict[str, Any], warnings: list[str] | None = None) -> BridgeCommandResult:
    return BridgeCommandResult(
        command_name=command_name,
        status="ok",
        data=redact_value(data),
        warnings=warnings or [],
        metadata={
            "bridge_version": "tauri-python-bridge.v1",
            "allowed_no_network_only": True,
            "blocked_engine_commands": sorted(FORBIDDEN_COMMANDS),
        },
    )


def _denied(command_name: str, code: str, message: str, *, details: dict[str, Any] | None = None) -> BridgeCommandResult:
    error = {"code": code, "message": message}
    if details:
        error["details"] = redact_value(details)
    return BridgeCommandResult(
        command_name=command_name,
        status="denied",
        errors=[error],
        metadata={"bridge_version": "tauri-python-bridge.v1", "allowed_no_network_only": True},
    )


def _from_contract(command_name: str, response: dict[str, Any]) -> BridgeCommandResult:
    status = "ok" if response.get("ok") else "error"
    errors = []
    if response.get("error"):
        errors.append(response["error"])
    return BridgeCommandResult(
        command_name=command_name,
        status=status,
        data=redact_value(response.get("result") or {}),
        warnings=list(response.get("warnings") or []),
        errors=redact_value(errors),
        metadata={
            "bridge_version": "tauri-python-bridge.v1",
            "engine_command": response.get("command"),
            "engine_contract_version": (response.get("metadata") or {}).get("contract_version"),
            "allowed_no_network_only": True,
        },
    )


def _validate_payload(value: Any, path: str = "payload") -> tuple[str, str] | None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in FORBIDDEN_KEYS:
                return "forbidden_payload_key", f"Payload key is not allowed: {path}.{key}"
            if key_text in {"command", "argv", "args", "shell", "executable", "module", "function"}:
                return "arbitrary_execution_shape_denied", f"Payload key is not allowed: {path}.{key}"
            error = _validate_payload(child, f"{path}.{key}")
            if error:
                return error
    elif isinstance(value, list):
        for index, child in enumerate(value):
            error = _validate_payload(child, f"{path}[{index}]")
            if error:
                return error
    elif isinstance(value, str):
        lower = value.lower()
        if REAL_PORTFOLIO_DOMAIN in lower:
            return "real_portfolio_url_denied", "Real portfolio URL is not accepted by the bridge stub"
        if any(blocked in lower for blocked in FORBIDDEN_COMMANDS):
            return "live_command_reference_denied", "Payload references a command that is not allowed through the bridge"
        if any(pattern.search(value) for pattern in TOKEN_PATTERNS):
            return "token_like_payload_denied", "Payload contains token-like text"
    return None


def _authorization_profile() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "owner": "desktop-bridge/placeholder",
        "allowed_domains": ["portfolio.example.test"],
        "allowed_cidrs": [],
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
        "environment": "staging",
        "allowed_impact_levels": ["green"],
        "request_budget": {"max_requests": 1, "max_requests_per_minute": 10, "max_concurrency": 1},
    }


def _planner_context(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "project_id": str(payload.get("project_id", "project_desktop_placeholder")),
        "target": PLACEHOLDER_TARGET,
        "normalized_target": PLACEHOLDER_TARGET,
        "scope_summary": {"allowed_domains": ["portfolio.example.test"], "safe_mode": True},
        "policy_summary": {"safe_mode": True, "allowed_impact_levels": ["green"]},
        "authorization_summary": {"owner_attested": True, "source": "placeholder_fixture"},
        "evidence_summary": {"evidence_ids": ["evidence_fetch_metadata", "evidence_header_csp"]},
        "finding_summary": {"candidate_count": 2, "confirmed_count": 0},
        "allowed_action_set": ["review_evidence", "generate_report", "build_attack_surface_graph"],
        "forbidden_action_set": ["live_http_fetch", "scanner_execution", "model_provider_execution"],
        "safety_constraints": ["no_network", "no_external_tools", "no_model_calls"],
        "redaction_applied": True,
    }


def _demo_attack_surface_fixture() -> dict[str, Any]:
    path = ROOT / "fixtures" / "demo" / "demo_attack_surface_input.json"
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis-ev-bridge", description="Aegis EV safe desktop bridge")
    parser.add_argument("--command", required=True, help="Allowlisted bridge command name")
    args = parser.parse_args(argv)
    raw = sys.stdin.read()
    if raw.strip():
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            result = _denied(args.command, "invalid_json", "Bridge payload must be JSON", details={"line": exc.lineno, "column": exc.colno})
            sys.stdout.write(result.to_json() + "\n")
            return 1
        if not isinstance(payload, dict):
            result = _denied(args.command, "invalid_payload_shape", "Bridge payload must be a JSON object")
            sys.stdout.write(result.to_json() + "\n")
            return 1
    else:
        payload = {}
    result = run_bridge_command(args.command, payload)
    sys.stdout.write(result.to_json() + "\n")
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
