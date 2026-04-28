import { useMemo, useState } from "react";
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
  reconSteps,
  remediation,
  targetScope
} from "./mockData";
import type { PipelineStage, ReconStepSummary, StatusTone } from "./types";

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
  const totalWarnings = useMemo(() => pipelineStages.reduce((count, stage) => count + stage.warnings.length, 0), []);

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
            <StatusChip label="Mock UI Only" tone="neutral" />
            <StatusChip label="Audit Valid" tone="good" />
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
          {active === "Overview" && <Overview totalWarnings={totalWarnings} />}
          {active === "Target & Scope" && <TargetScope />}
          {active === "Operator Pipeline" && <OperatorPipeline />}
          {active === "Findings" && <Findings />}
          {active === "Evidence" && <Evidence />}
          {active === "Attack Surface" && <AttackSurface />}
          {active === "Recon Plan" && <ReconPlan />}
          {active === "Remediation & Retest" && <RemediationRetest />}
          {active === "Reports" && <Reports />}
          {active === "Approvals" && <Approvals />}
          {active === "AI Guardrails" && <AIGuardrails />}
          {active === "Settings" && <Settings />}
        </section>
      </main>
    </div>
  );
}

function Overview({ totalWarnings }: { totalWarnings: number }) {
  return (
    <>
      <div className="summary-grid">
        <SummaryCard title="Project" value={projectSummary.projectName} detail={projectSummary.targetUrl} />
        <SummaryCard title="Safe Mode" value="Enabled" detail="Low-impact workflows only" />
        <SummaryCard title="Authorization" value="Owner-attested" detail={projectSummary.environment} />
        <SummaryCard title="Live Request" value="Mock" detail="No live sidecar call from UI" />
        <SummaryCard title="Candidate Findings" value={projectSummary.findingCount} detail="Not confirmed exploitability" />
        <SummaryCard title="Evidence" value={projectSummary.evidenceCount} detail="Redacted, body-free" />
        <SummaryCard title="Audit" value="Valid" detail="Mock verification status" />
        <SummaryCard title="Pipeline" value="Ready" detail={`${totalWarnings} safety notes`} />
      </div>
      <section className="panel">
        <h3>Operator Readiness</h3>
        <p>
          This shell presents the full Aegis EV workflow from scoped target setup through remediation and retest. It is a non-executing UI layer:
          no sidecar, scanner, crawler, external tool, or model provider is called.
        </p>
      </section>
      <EngineConnectionPanel />
    </>
  );
}

function TargetScope() {
  return (
    <div className="two-column">
      <section className="panel">
        <h3>Allowed Scope</h3>
        <dl className="definition-list">
          <dt>Domain</dt>
          <dd>{targetScope.allowedDomain}</dd>
          <dt>Schemes</dt>
          <dd>{targetScope.allowedSchemes.join(", ")}</dd>
          <dt>Environment</dt>
          <dd>{targetScope.environment}</dd>
          <dt>Attestation</dt>
          <dd>{targetScope.attestation}</dd>
        </dl>
      </section>
      <section className="panel panel--muted">
        <h3>Denied Example</h3>
        <p className="mono">{targetScope.outOfScopeExample}</p>
        <ul className="plain-list">
          {targetScope.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function OperatorPipeline() {
  return (
    <div className="stage-grid">
      {pipelineStages.map((stage) => (
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

function Findings() {
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

function Evidence() {
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

function Reports() {
  return (
    <section className="panel">
      <DataTable
        columns={["Report", "Format", "Status", "Notes"]}
        rows={[
          ["Portfolio Operator Summary", "Markdown", "mock-ready", "Evidence-backed narrative only"],
          ["Portfolio Operator Data", "JSON", "mock-ready", "Structured output for UI integration"],
          ["Audit Chain", "JSONL", "mock-valid", "No PDF generation in this task"]
        ]}
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
