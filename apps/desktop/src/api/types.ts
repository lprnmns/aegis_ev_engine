export type BridgeCommandName =
  | "engine_health"
  | "run_local_demo_flow_no_network"
  | "build_ai_planner_packet"
  | "list_model_providers"
  | "list_tool_capabilities"
  | "build_attack_surface_graph_from_fixture"
  | "map_vulnerability_intelligence_from_fixture";

export interface BridgeCommandRequest {
  command_name: BridgeCommandName;
  payload?: Record<string, unknown>;
}

export interface BridgeError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface BridgeCommandResult {
  command_name: string;
  status: "ok" | "error" | "denied";
  data: Record<string, unknown>;
  warnings: string[];
  errors: BridgeError[];
  redaction_applied: boolean;
  executed_live_network: false;
  executed_external_tool: false;
  metadata: Record<string, unknown>;
}

export interface EngineHealthResult {
  engine: string;
  bridge_mode: string;
  safe_mode_default: boolean;
  live_portfolio_execution_enabled: boolean;
  external_tool_execution_enabled: boolean;
  model_provider_execution_enabled: boolean;
  allowed_commands: BridgeCommandName[];
}

export interface LocalDemoSummary {
  demo_id?: string;
  no_network?: boolean;
  evidence_count?: number;
  finding_count?: number;
  reports?: Record<string, unknown>;
}
