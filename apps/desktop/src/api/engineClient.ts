import type { BridgeCommandName, BridgeCommandRequest, BridgeCommandResult } from "./types";

type TauriInvoke = <T>(command: string, args: Record<string, unknown>) => Promise<T>;

const mockResults: Record<BridgeCommandName, BridgeCommandResult> = {
  engine_health: {
    command_name: "engine_health",
    status: "ok",
    data: {
      engine: "aegis_ev",
      bridge_mode: "mock_fallback_no_network_stub",
      safe_mode_default: true,
      live_portfolio_execution_enabled: false,
      external_tool_execution_enabled: false,
      model_provider_execution_enabled: false,
      allowed_commands: [
        "engine_health",
        "run_local_demo_flow_no_network",
        "build_ai_planner_packet",
        "list_model_providers",
        "list_tool_capabilities",
        "build_attack_surface_graph_from_fixture",
        "map_vulnerability_intelligence_from_fixture"
      ]
    },
    warnings: ["Tauri runtime was not detected; showing deterministic mock fallback."],
    errors: [],
    redaction_applied: true,
    executed_live_network: false,
    executed_external_tool: false,
    metadata: { bridge_version: "frontend-mock-bridge.v1", allowed_no_network_only: true }
  },
  run_local_demo_flow_no_network: fallback("run_local_demo_flow_no_network", {
    demo: { no_network: true, evidence_count: 8, finding_count: 4, reports: { markdown: "mock", json: "mock" } }
  }),
  build_ai_planner_packet: fallback("build_ai_planner_packet", {
    packet: { role: "planner", redaction_applied: true, model_call_performed: false }
  }),
  list_model_providers: fallback("list_model_providers", {
    providers: [{ provider_id: "mock_safe_provider", enabled: true, requires_network: false, safe_for_local_tests: true }]
  }),
  list_tool_capabilities: fallback("list_tool_capabilities", {
    tool_count: 5,
    execution_policy: "metadata_and_dry_run_only"
  }),
  build_attack_surface_graph_from_fixture: fallback("build_attack_surface_graph_from_fixture", {
    graph: { target_count: 1, technology_count: 2, evidence_count: 2 }
  }),
  map_vulnerability_intelligence_from_fixture: fallback("map_vulnerability_intelligence_from_fixture", {
    mapping: { match_count: 4, confirmed_vulnerabilities: 0 }
  })
};

export async function runEngineBridgeCommand(request: BridgeCommandRequest): Promise<BridgeCommandResult> {
  const invoke = await resolveTauriInvoke();
  if (!invoke) {
    return mockResults[request.command_name];
  }
  return invoke<BridgeCommandResult>("run_engine_bridge_command", { request });
}

async function resolveTauriInvoke(): Promise<TauriInvoke | null> {
  if (!("__TAURI_INTERNALS__" in globalThis)) {
    return null;
  }
  try {
    const api = await import("@tauri-apps/api/core");
    return api.invoke as TauriInvoke;
  } catch {
    return null;
  }
}

function fallback(commandName: BridgeCommandName, data: Record<string, unknown>): BridgeCommandResult {
  return {
    command_name: commandName,
    status: "ok",
    data,
    warnings: ["Tauri runtime was not detected; showing deterministic mock fallback."],
    errors: [],
    redaction_applied: true,
    executed_live_network: false,
    executed_external_tool: false,
    metadata: { bridge_version: "frontend-mock-bridge.v1", allowed_no_network_only: true }
  };
}
