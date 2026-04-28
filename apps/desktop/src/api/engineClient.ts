import type { BridgeCommandName, BridgeCommandRequest, BridgeCommandResult, LocalDemoSummary } from "./types";
import type { EvidenceSummary, FindingSummary, LocalDemoRunSummary, PipelineStage, ProjectSummary, ReportSummary, TargetScopeSummary } from "../types";

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
  run_local_demo_flow_no_network: fallback("run_local_demo_flow_no_network", { demo: mockLocalDemoSummary() }),
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

export async function runLocalDemoFlow(): Promise<{ bridgeResult: BridgeCommandResult; demo: LocalDemoRunSummary }> {
  const bridgeResult = await runEngineBridgeCommand({ command_name: "run_local_demo_flow_no_network", payload: {} });
  if (bridgeResult.status !== "ok") {
    throw new Error(normalizeBridgeErrors(bridgeResult).join("; ") || "Local demo failed");
  }
  return { bridgeResult, demo: normalizeLocalDemoSummary(bridgeResult) };
}

export function normalizeBridgeErrors(result: BridgeCommandResult): string[] {
  return result.errors.length > 0 ? result.errors.map((error) => `${error.code}: ${error.message}`) : result.warnings;
}

export function normalizeLocalDemoSummary(result: BridgeCommandResult): LocalDemoRunSummary {
  const demo = (result.data.demo ?? {}) as LocalDemoSummary;
  const projectRaw = (demo.project_summary ?? {}) as Record<string, unknown>;
  const scopeRaw = (demo.target_scope_summary ?? {}) as Record<string, unknown>;
  const audit = (demo.audit_verification_status ?? {}) as Record<string, unknown>;
  const evidenceCount = Number(projectRaw.evidence_count ?? demo.evidence_count ?? 0);
  const findingCount = Number(projectRaw.finding_count ?? demo.finding_count ?? 0);
  const auditValid = audit.valid === true || projectRaw.audit_status === "valid";
  const project: ProjectSummary = {
    projectName: text(projectRaw.project_name, "Aegis EV Local Demo Project"),
    targetUrl: text(projectRaw.target_url, "https://portfolio.example.test"),
    environment: environment(projectRaw.environment),
    safeMode: Boolean(projectRaw.safe_mode ?? true),
    authorization: "owner-attested",
    liveRequestMode: "local-demo",
    pipelineStatus: "completed",
    evidenceCount,
    findingCount,
    auditStatus: auditValid ? "valid" : "not-run"
  };
  const targetScope: TargetScopeSummary = {
    allowedDomain: array(scopeRaw.allowed_domains).join(", ") || "portfolio.example.test",
    allowedSchemes: array(scopeRaw.allowed_schemes).length > 0 ? array(scopeRaw.allowed_schemes) : ["https"],
    environment: text(scopeRaw.environment, project.environment),
    attestation: text(scopeRaw.authorization_attestation, "Placeholder owner-attestation model; no live request was made."),
    outOfScopeExample: "https://api.portfolio.example.test/admin-preview",
    notes: [
      "Local demo uses committed fixtures only.",
      "No live request, scanner, crawler, fuzzer, external tool, or model provider was executed.",
      `${Number(scopeRaw.target_count ?? 0)} placeholder target(s) were modeled in scope.`
    ]
  };
  return {
    project,
    targetScope,
    pipelineStages: normalizePipelineStages(demo.pipeline_stage_summaries ?? []),
    findings: normalizeFindings(demo.finding_summaries ?? []),
    evidenceRows: normalizeEvidence(demo.evidence_summaries ?? []),
    reports: normalizeReports(demo.report_summaries ?? []),
    auditStatus: auditValid ? `valid (${Number(audit.event_count ?? 0)} events)` : "not-run",
    warnings: [...result.warnings, ...array(demo.warnings)],
    errors: array(demo.errors),
    safetyFlags: {
      executedLiveNetwork: false,
      executedExternalTool: false,
      executedScanner: false,
      executedCrawler: false,
      executedFuzzer: false,
      calledModelProvider: false,
      requiredProviderCredential: false,
      storedRawBody: false
    }
  };
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

function mockLocalDemoSummary(): LocalDemoSummary {
  return {
    no_network: true,
    evidence_count: 15,
    finding_count: 6,
    project_summary: {
      project_name: "Aegis EV Local Demo Project",
      target_url: "https://portfolio.example.test",
      environment: "staging",
      safe_mode: true,
      evidence_count: 15,
      finding_count: 6,
      audit_status: "valid"
    },
    target_scope_summary: {
      allowed_domains: ["portfolio.example.test", "api.portfolio.example.test"],
      allowed_schemes: ["https"],
      environment: "staging",
      target_count: 2,
      authorization_attestation: "Placeholder owner-attestation model; no live request was made."
    },
    pipeline_stage_summaries: [
      { id: "project_scope_created", name: "Project and scope created", status: "completed", evidence_count: 0, warnings: [] },
      { id: "imports_processed", name: "Fixture imports processed", status: "completed", evidence_count: 3, warnings: [] },
      { id: "header_checks", name: "Supplied header checks", status: "completed", evidence_count: 12, warnings: [] },
      { id: "findings_generated", name: "Candidate findings generated", status: "completed", evidence_count: 6, warnings: ["Findings are candidate observations only."] },
      { id: "report_generated", name: "Markdown and JSON report generated", status: "completed", evidence_count: 15, warnings: [] },
      { id: "audit_verified", name: "Audit chain verified", status: "completed", evidence_count: 8, warnings: [] }
    ],
    evidence_summaries: [
      { id: "evidence_demo_header_csp", source_type: "web_header_check", title: "Header check: CSP", summary: "CSP absent in supplied fixture metadata.", redaction_applied: true, body_stored: false },
      { id: "evidence_demo_import_openapi", source_type: "api_import", title: "OpenAPI fixture import", summary: "Placeholder endpoints imported from committed fixture.", redaction_applied: true, body_stored: false }
    ],
    finding_summaries: [
      { id: "finding_demo_header_csp", title: "Missing Content-Security-Policy header", severity: "medium", status: "candidate", verification: "evidence_backed", retest_status: "not_retested", evidence_ids: ["evidence_demo_header_csp"] }
    ],
    report_summaries: [
      { title: "Local Demo Markdown Report", format: "markdown", status: "generated", path: null, summary: "Evidence-backed fixture report; no live target request." },
      { title: "Local Demo JSON Report", format: "json", status: "generated", path: null, summary: "Structured fixture report data; no raw bodies or secrets." }
    ],
    audit_verification_status: { valid: true, event_count: 8 },
    safety_flags: {
      executed_live_network: false,
      executed_external_tool: false,
      executed_scanner: false,
      executed_crawler: false,
      executed_fuzzer: false,
      called_model_provider: false,
      required_provider_credential: false,
      stored_raw_body: false
    }
  };
}

function normalizePipelineStages(items: Array<Record<string, unknown>>): PipelineStage[] {
  return items.map((item) => ({
    id: text(item.id, text(item.name, "stage")).replaceAll(" ", "_").toLowerCase(),
    name: text(item.name, "Demo stage"),
    status: stageStatus(item.status),
    evidenceCount: Number(item.evidence_count ?? 0),
    warnings: array(item.warnings),
    safetyNote: "Local fixture data only; no live request or external execution."
  }));
}

function normalizeFindings(items: Array<Record<string, unknown>>): FindingSummary[] {
  return items.map((item, index) => ({
    id: text(item.id, `finding_${index}`),
    title: text(item.title, "Candidate observation"),
    severity: severity(item.severity),
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: retestStatus(item.retest_status),
    evidenceIds: array(item.evidence_ids)
  }));
}

function normalizeEvidence(items: Array<Record<string, unknown>>): EvidenceSummary[] {
  return items.map((item, index) => ({
    id: text(item.id, `evidence_${index}`),
    sourceType: text(item.source_type, "unknown"),
    title: text(item.title, "Evidence"),
    summary: text(item.summary, "Redacted local demo evidence."),
    redactionApplied: Boolean(item.redaction_applied ?? true),
    bodyStored: Boolean(item.body_stored ?? false)
  }));
}

function normalizeReports(items: Array<Record<string, unknown>>): ReportSummary[] {
  return items.map((item) => ({
    title: text(item.title, "Local Demo Report"),
    format: text(item.format, "json"),
    status: text(item.status, "generated"),
    path: typeof item.path === "string" ? item.path : null,
    summary: text(item.summary, "Report summary generated from fixture data.")
  }));
}

function text(value: unknown, fallbackValue: string): string {
  return typeof value === "string" && value.trim() ? value : fallbackValue;
}

function array(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function environment(value: unknown): "development" | "staging" | "production" {
  return value === "development" || value === "production" ? value : "staging";
}

function severity(value: unknown): "info" | "low" | "medium" | "high" {
  return value === "low" || value === "medium" || value === "high" ? value : "info";
}

function retestStatus(value: unknown): "not_retested" | "appears_resolved" | "still_present" | "inconclusive" {
  if (value === "appears_resolved" || value === "still_present" || value === "inconclusive") return value;
  return "not_retested";
}

function stageStatus(value: unknown): PipelineStage["status"] {
  if (value === "completed" || value === "warning" || value === "blocked" || value === "disabled" || value === "ready") return value;
  return "mocked";
}
