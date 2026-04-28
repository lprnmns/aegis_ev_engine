import { useMemo, useState } from "react";
import { runLocalDemoFlow } from "./api/engineClient";
import { StatusChip } from "./components/StatusChip";
import { SummaryCard } from "./components/SummaryCard";
import { EngineConnectionPanel } from "./components/EngineConnectionPanel";
import {
  aiGuardrails,
  approvals,
  attackSurface,
  evidenceRows,
  findings,
  pipelineStages,
  projectSummary,
  reportRows,
  reconSteps,
  remediation,
  targetScope
} from "./mockData";
import type {
  EvidenceSummary,
  FindingSummary,
  LocalDemoRunSummary,
  PipelineStage,
  ProjectSummary,
  ReconStepSummary,
  ReportSummary,
  StatusTone,
  TargetScopeSummary
} from "./types";

const navItems = [
  "Overview",
  "Target & Scope",
  "Operator Pipeline",
  "Findings",
  "Evidence",
  "Attack Surface",
  "Recon Plan",
  "Remediation & Retest",
  "Reports",
  "Approvals",
  "AI Guardrails",
  "Settings"
] as const;

type NavItem = (typeof navItems)[number];

function toneForStage(stage: PipelineStage): StatusTone {
  if (stage.status === "blocked") return "danger";
  if (stage.status === "disabled") return "neutral";
  if (stage.warnings.length > 0) return "warn";
  return "good";
}

function toneForImpact(step: ReconStepSummary): StatusTone {
  if (step.impact === "red") return "danger";
  if (step.impact === "amber") return "warn";
  return "good";
}

export default function App() {
  const [active, setActive] = useState<NavItem>("Overview");
  const [demoRun, setDemoRun] = useState<LocalDemoRunSummary | null>(null);
  const [demoStatus, setDemoStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [demoError, setDemoError] = useState<string | null>(null);
  const activeProject = demoRun?.project ?? projectSummary;
  const activeScope = demoRun?.targetScope ?? targetScope;
  const activeStages = demoRun?.pipelineStages ?? pipelineStages;
  const activeFindings = demoRun?.findings ?? findings;
  const activeEvidence = demoRun?.evidenceRows ?? evidenceRows;
  const activeReports = demoRun?.reports ?? reportRows;
  const totalWarnings = useMemo(() => activeStages.reduce((count, stage) => count + stage.warnings.length, 0), [activeStages]);

  async function handleRunLocalDemo() {
    setDemoStatus("loading");
    setDemoError(null);
    try {
      const result = await runLocalDemoFlow();
      setDemoRun(result.demo);
      setDemoStatus("success");
    } catch (error) {
      setDemoError(error instanceof Error ? error.message : "Local demo failed");
      setDemoStatus("error");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">AE</div>
          <div>
            <h1>Aegis EV</h1>
            <p>Authorized exposure validation</p>
          </div>
        </div>
        <nav className="nav-list" aria-label="Primary">
          {navItems.map((item) => (
            <button key={item} className={item === active ? "nav-item nav-item--active" : "nav-item"} onClick={() => setActive(item)}>
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <label htmlFor="project-select">Project</label>
            <select id="project-select" value="portfolio-demo" disabled>
              <option value="portfolio-demo">Portfolio Demo</option>
            </select>
          </div>
          <div className="topbar__status">
            <StatusChip label="Safe Mode Enabled" tone="good" />
            <StatusChip label="Owner-Attested Scope" tone="info" />
            <StatusChip label={demoRun ? "Local Demo Loaded" : "Mock Fallback Ready"} tone={demoRun ? "good" : "neutral"} />
            <StatusChip label={activeProject.auditStatus === "valid" ? "Audit Valid" : "Audit Pending"} tone={activeProject.auditStatus === "valid" ? "good" : "neutral"} />
          </div>
        </header>

        <section className="page">
          <div className="page-heading">
            <div>
              <h2>{active}</h2>
              <p>Desktop shell uses static placeholder data only. Live sidecar execution is intentionally not wired.</p>
            </div>
            <StatusChip label="No scans or model calls" tone="good" />
          </div>
          {active === "Overview" && (
            <Overview
              totalWarnings={totalWarnings}
              project={activeProject}
              demoRun={demoRun}
              demoStatus={demoStatus}
              demoError={demoError}
              onRunLocalDemo={handleRunLocalDemo}
            />
          )}
          {active === "Target & Scope" && <TargetScope scope={activeScope} />}
          {active === "Operator Pipeline" && <OperatorPipeline stages={activeStages} />}
          {active === "Findings" && <Findings findings={activeFindings} />}
          {active === "Evidence" && <Evidence evidenceRows={activeEvidence} />}
          {active === "Attack Surface" && <AttackSurface />}
          {active === "Recon Plan" && <ReconPlan />}
          {active === "Remediation & Retest" && <RemediationRetest />}
          {active === "Reports" && <Reports reports={activeReports} />}
          {active === "Approvals" && <Approvals />}
          {active === "AI Guardrails" && <AIGuardrails />}
          {active === "Settings" && <Settings />}
        </section>
      </main>
    </div>
  );
}

function Overview({
  totalWarnings,
  project,
  demoRun,
  demoStatus,
  demoError,
  onRunLocalDemo
}: {
  totalWarnings: number;
  project: ProjectSummary;
  demoRun: LocalDemoRunSummary | null;
  demoStatus: "idle" | "loading" | "success" | "error";
  demoError: string | null;
  onRunLocalDemo: () => void;
}) {
  return (
    <>
      <div className="summary-grid">
        <SummaryCard title="Project" value={project.projectName} detail={project.targetUrl} />
        <SummaryCard title="Safe Mode" value="Enabled" detail="Low-impact workflows only" />
        <SummaryCard title="Authorization" value="Owner-attested" detail={project.environment} />
        <SummaryCard title="Live Request" value="None" detail="Local fixture flow only" />
        <SummaryCard title="Candidate Findings" value={project.findingCount} detail="Not confirmed exploitability" />
        <SummaryCard title="Evidence" value={project.evidenceCount} detail="Redacted, body-free" />
        <SummaryCard title="Audit" value={project.auditStatus === "valid" ? "Valid" : "Pending"} detail={demoRun?.auditStatus ?? "Mock verification status"} />
        <SummaryCard title="Pipeline" value={project.pipelineStatus} detail={`${totalWarnings} safety notes`} />
      </div>
      <section className="panel local-demo-panel">
        <div className="panel-row">
          <div>
            <h3>Local No-Network Demo</h3>
            <p>Run the committed fixture flow through the safe bridge and update this UI with structured engine summaries.</p>
          </div>
          <div className="list-card__chips">
            <StatusChip label="no live target request" tone="good" />
            <StatusChip label="no scanner/crawler/fuzzer" tone="good" />
            <StatusChip label="no model call" tone="good" />
          </div>
        </div>
        <button className="primary-action" onClick={onRunLocalDemo} disabled={demoStatus === "loading"}>
          {demoStatus === "loading" ? "Running Local Demo..." : "Run Local Demo"}
        </button>
        <StatusChip label={demoStatus} tone={demoStatus === "error" ? "danger" : demoStatus === "success" ? "good" : "neutral"} />
        {demoError ? <p className="error-text">{demoError}</p> : null}
        {demoRun ? (
          <div className="demo-result-strip">
            <span>Evidence: {demoRun.project.evidenceCount}</span>
            <span>Candidate findings: {demoRun.project.findingCount}</span>
            <span>Audit: {demoRun.auditStatus}</span>
            <span>Reports: {demoRun.reports.length}</span>
          </div>
        ) : null}
      </section>
      <section className="panel">
        <h3>Operator Readiness</h3>
        <p>
          This shell presents the full Aegis EV workflow from scoped target setup through remediation and retest. TASK-026 allows only
          the local fixture demo bridge command; no live portfolio run, scanner, crawler, external tool, or model provider is called.
        </p>
      </section>
      <EngineConnectionPanel />
    </>
  );
}

function TargetScope({ scope }: { scope: TargetScopeSummary }) {
  return (
    <div className="two-column">
      <section className="panel">
        <h3>Allowed Scope</h3>
        <dl className="definition-list">
          <dt>Domain</dt>
          <dd>{scope.allowedDomain}</dd>
          <dt>Schemes</dt>
          <dd>{scope.allowedSchemes.join(", ")}</dd>
          <dt>Environment</dt>
          <dd>{scope.environment}</dd>
          <dt>Attestation</dt>
          <dd>{scope.attestation}</dd>
        </dl>
      </section>
      <section className="panel panel--muted">
        <h3>Denied Example</h3>
        <p className="mono">{scope.outOfScopeExample}</p>
        <ul className="plain-list">
          {scope.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function OperatorPipeline({ stages }: { stages: PipelineStage[] }) {
  return (
    <div className="stage-grid">
      {stages.map((stage) => (
        <section key={stage.id} className="panel stage-panel">
          <div className="panel-row">
            <h3>{stage.name}</h3>
            <StatusChip label={stage.status} tone={toneForStage(stage)} />
          </div>
          <p>{stage.safetyNote}</p>
          <div className="mini-meta">{stage.evidenceCount} evidence record(s)</div>
          {stage.warnings.length > 0 ? (
            <ul className="warning-list">
              {stage.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
        </section>
      ))}
    </div>
  );
}

function Findings({ findings }: { findings: FindingSummary[] }) {
  return (
    <section className="panel">
      <DataTable
        columns={["Finding", "Severity", "Status", "Verification", "Retest"]}
        rows={findings.map((finding) => [
          finding.title,
          finding.severity,
          finding.status,
          finding.verification,
          finding.retestStatus
        ])}
      />
      <p className="footnote">All findings are candidate observations. This UI does not claim confirmed exploitability.</p>
    </section>
  );
}

function Evidence({ evidenceRows }: { evidenceRows: EvidenceSummary[] }) {
  return (
    <section className="panel">
      <DataTable
        columns={["Evidence", "Source", "Summary", "Body Stored", "Redacted"]}
        rows={evidenceRows.map((row) => [row.title, row.sourceType, row.summary, row.bodyStored ? "yes" : "no", row.redactionApplied ? "yes" : "no"])}
      />
    </section>
  );
}

function AttackSurface() {
  return (
    <div className="two-column">
      <section className="panel">
        <h3>Graph Summary</h3>
        <div className="summary-grid summary-grid--compact">
          <SummaryCard title="Targets" value={attackSurface.targets} />
          <SummaryCard title="Technologies" value={attackSurface.technologies.length} />
          <SummaryCard title="Missing Controls" value={attackSurface.missingControls.length} />
          <SummaryCard title="Evidence Coverage" value={attackSurface.evidenceCoverage} />
        </div>
      </section>
      <section className="panel">
        <h3>Surface Hints</h3>
        <TagCloud values={[...attackSurface.technologies, ...attackSurface.missingControls, ...attackSurface.hypotheses]} />
      </section>
    </div>
  );
}

function ReconPlan() {
  return (
    <section className="panel">
      <div className="card-list">
        {reconSteps.map((step) => (
          <article key={step.id} className="list-card">
            <div>
              <h3>{step.title}</h3>
              <p>{step.rationale}</p>
            </div>
            <div className="list-card__chips">
              <StatusChip label={step.impact} tone={toneForImpact(step)} />
              <StatusChip label={step.status} tone={step.status === "blocked" ? "danger" : step.status === "requires_approval" ? "warn" : "good"} />
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function RemediationRetest() {
  return (
    <div className="two-column">
      <section className="panel">
        <h3>{remediation.findingTitle}</h3>
        <ul className="plain-list mono-list">
          {remediation.recommendedHeaders.map((header) => (
            <li key={header}>{header}</li>
          ))}
        </ul>
        <button className="disabled-action" disabled>
          Live retest disabled
        </button>
        <p className="footnote">{remediation.disabledActionReason}</p>
      </section>
      <section className="panel">
        <h3>Retest Status Definitions</h3>
        {remediation.retestDefinitions.map((item) => (
          <div className="definition-item" key={item.status}>
            <StatusChip label={item.status} tone={item.status === "appears_resolved" ? "good" : item.status === "still_present" ? "warn" : "info"} />
            <p>{item.meaning}</p>
          </div>
        ))}
      </section>
    </div>
  );
}

function Reports({ reports }: { reports: ReportSummary[] }) {
  return (
    <section className="panel">
      <DataTable
        columns={["Report", "Format", "Status", "Notes"]}
        rows={reports.map((report) => [report.title, report.format, report.status, report.path ? `${report.summary} (${report.path})` : report.summary])}
      />
    </section>
  );
}

function Approvals() {
  return (
    <section className="panel">
      <DataTable
        columns={["Approval", "Status", "Requester", "Note"]}
        rows={approvals.map((approval) => [approval.title, approval.status, approval.requester, approval.note])}
      />
    </section>
  );
}

function AIGuardrails() {
  return (
    <div className="two-column">
      <section className="panel">
        <h3>Roles</h3>
        <TagCloud values={aiGuardrails.roles} />
        <p>{aiGuardrails.providerStatus}</p>
        <StatusChip label={aiGuardrails.routerMode} tone="good" />
        <StatusChip label={`validation ${aiGuardrails.validationStatus}`} tone="good" />
      </section>
      <section className="panel panel--muted">
        <h3>Guardrail Notes</h3>
        <ul className="plain-list">
          {aiGuardrails.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function Settings() {
  return (
    <>
      <EngineConnectionPanel />
      <div className="stage-grid">
        {[
          ["Model providers", "Disabled future settings; mock provider only."],
          ["Python sidecar path", "Bridge uses fixed development path resolution; no user path is stored."],
          ["Local output directory", "Future setting; no files are read here."],
          ["Safe-mode budgets", "Read-only placeholder for future policy integration."]
        ].map(([title, detail]) => (
          <section className="panel panel--muted" key={title}>
            <h3>{title}</h3>
            <p>{detail}</p>
            <StatusChip label="future-disabled" tone="neutral" />
          </section>
        ))}
      </div>
    </>
  );
}

function DataTable({ columns, rows }: { columns: string[]; rows: string[][] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.join("|")}>
              {row.map((cell, index) => (
                <td key={`${cell}-${index}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TagCloud({ values }: { values: string[] }) {
  return (
    <div className="tag-cloud">
      {values.map((value) => (
        <span className="tag" key={value}>
          {value}
        </span>
      ))}
    </div>
  );
}
