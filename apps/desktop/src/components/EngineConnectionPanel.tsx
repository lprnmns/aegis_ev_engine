import { useState } from "react";
import { runEngineBridgeCommand } from "../api/engineClient";
import type { BridgeCommandName, BridgeCommandResult } from "../api/types";
import { StatusChip } from "./StatusChip";

const bridgeActions: Array<{ command: BridgeCommandName; label: string; note: string }> = [
  { command: "engine_health", label: "Check Engine Health", note: "Bridge status and allowlist only." },
  { command: "run_local_demo_flow_no_network", label: "Run Local Demo Fixture", note: "Committed fixture flow, no network." },
  { command: "list_tool_capabilities", label: "List Tool Capabilities", note: "Metadata only, no execution." },
  { command: "build_ai_planner_packet", label: "Build AI Planner Packet", note: "No model provider call." }
];

export function EngineConnectionPanel() {
  const [loading, setLoading] = useState<BridgeCommandName | null>(null);
  const [result, setResult] = useState<BridgeCommandResult | null>(null);

  async function run(command: BridgeCommandName) {
    setLoading(command);
    try {
      const response = await runEngineBridgeCommand({ command_name: command, payload: {} });
      setResult(response);
    } catch (error) {
      setResult({
        command_name: command,
        status: "error",
        data: {},
        warnings: [],
        errors: [{ code: "ui_bridge_error", message: error instanceof Error ? error.message : "Bridge call failed" }],
        redaction_applied: true,
        executed_live_network: false,
        executed_external_tool: false,
        metadata: { bridge_version: "ui-error-boundary.v1" }
      });
    } finally {
      setLoading(null);
    }
  }

  return (
    <section className="panel bridge-panel">
      <div className="panel-row">
        <div>
          <h3>Engine Bridge Stub</h3>
          <p>Allowlisted Python engine commands only. Live target requests, model calls, scanners, crawlers, and external tools remain disabled.</p>
        </div>
        <div className="list-card__chips">
          <StatusChip label="no live target request" tone="good" />
          <StatusChip label="no model call" tone="good" />
          <StatusChip label="no external tool" tone="good" />
        </div>
      </div>
      <div className="bridge-actions">
        {bridgeActions.map((action) => (
          <button key={action.command} className="bridge-action" onClick={() => run(action.command)} disabled={loading !== null}>
            <span>{loading === action.command ? "Running..." : action.label}</span>
            <small>{action.note}</small>
          </button>
        ))}
      </div>
      <div className="bridge-result">
        <div className="panel-row">
          <h4>Structured Result</h4>
          <StatusChip label={result ? result.status : "mock fallback ready"} tone={!result || result.status === "ok" ? "good" : "warn"} />
        </div>
        <pre>{JSON.stringify(result ?? { status: "idle", note: "Select a safe bridge command to view JSON output." }, null, 2)}</pre>
      </div>
    </section>
  );
}
