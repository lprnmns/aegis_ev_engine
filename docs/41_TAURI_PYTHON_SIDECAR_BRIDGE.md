# TASK-025 Tauri Python Sidecar Bridge Stub

## Purpose

TASK-025 adds the first safe Tauri-to-Python bridge stub for the Aegis EV desktop shell. The bridge lets the UI call a small allowlist of no-network, no-side-effect engine commands and receive structured JSON.

## What It Does

- Adds a Python bridge wrapper at `engine/src/aegis_ev/bridge.py`.
- Adds a Tauri invoke command named `run_engine_bridge_command`.
- Adds a TypeScript engine client and an Engine Bridge panel in the desktop UI.
- Supports deterministic mock fallback when the UI is not running inside Tauri.
- Allows only bridge-safe commands:
  - `engine_health`
  - `run_local_demo_flow_no_network`
  - `build_ai_planner_packet`
  - `list_model_providers`
  - `list_tool_capabilities`
  - `build_attack_surface_graph_from_fixture`
  - `map_vulnerability_intelligence_from_fixture`
- Rejects unknown commands, live portfolio commands, live HTTP commands, arbitrary argv/module/function payloads, secret-like keys, token-like strings, and the real portfolio URL.

## What It Does Not Do

- It does not wire live portfolio operator execution into the UI.
- It does not perform live HTTP fetches from the UI.
- It does not run scanners, crawlers, fuzzers, or external security tools.
- It does not call model providers.
- It does not require API keys.
- It does not accept arbitrary shell commands or arbitrary Python module/function names.
- It does not configure broad Tauri shell permissions or sidecar execution.

## JSON Request And Response

The Tauri command accepts:

```json
{
  "command_name": "engine_health",
  "payload": {}
}
```

It returns:

```json
{
  "command_name": "engine_health",
  "status": "ok",
  "data": {},
  "warnings": [],
  "errors": [],
  "redaction_applied": true,
  "executed_live_network": false,
  "executed_external_tool": false,
  "metadata": {}
}
```

The Python bridge returns the same shape when invoked directly:

```bash
cd engine
PYTHONPATH=src python3 -m aegis_ev.bridge --command engine_health
```

## Security Checks

The bridge enforces:

- Fixed command names only.
- Internal argv construction only.
- JSON payload validation before engine dispatch.
- No live portfolio command allowlisting.
- No live HTTP command allowlisting.
- No arbitrary executable, shell, module, function, args, or argv payload keys.
- No secret-bearing keys such as authorization, cookies, bearer values, passwords, or secrets.
- No real portfolio URL in bridge payloads or tracked files.
- Response flags that explicitly state no live network or external tool execution occurred.

## UI Mapping

The desktop UI exposes safe buttons for:

- Check Engine Health.
- Run Local Demo Fixture.
- List Tool Capabilities.
- Build AI Planner Packet.

Each button calls the TypeScript bridge client. Outside a Tauri runtime, the UI displays deterministic mock fallback data and labels that no live target request, model call, or external tool execution occurred.

## Future Work

Future tasks may safely enable selected live commands only with explicit scope, owner authorization, policy gating, approval boundaries, audit events, and no arbitrary passthrough. TASK-026 remains local fixture-only.

Not implemented yet:

- Live portfolio operator execution from UI.
- Real sidecar packaging.
- Arbitrary project persistence.
- External tool execution.
- Model provider execution.
- Installer.
