# TASK-024 Tauri Desktop UI Shell

## Purpose

TASK-024 adds the first Tauri-compatible desktop UI shell for Aegis EV. It presents the product as a professional authorized security validation/operator workbench using static mock data only.

## What It Does

- Adds `apps/desktop/` with React, TypeScript, Vite, and Tauri-compatible structure.
- Adds a modern workbench shell with sidebar navigation, top status bar, project selector placeholder, safe-mode indicator, scope indicator, pipeline status, evidence status, and audit status.
- Adds mock screens for overview, target scope, operator pipeline, findings, evidence, attack surface, recon plan, remediation and retest, reports, approvals, AI guardrails, and settings.
- Adds TypeScript types that mirror existing engine summaries.
- Adds deterministic mock data using only placeholder domains.
- Adds a lightweight static validation script that does not require installing dependencies.

## What It Does Not Do

- It does not call the Python engine.
- It does not configure or run a sidecar.
- It does not execute shell commands from the UI.
- It does not scan, crawl, fuzz, run external tools, or call model providers.
- It does not read provider config, browser sessions, cookies, tokens, or credentials.
- It does not require API keys.
- It does not generate PDF reports.

## Placeholder Data

The UI uses only:

- `https://portfolio.example.test`
- `api.portfolio.example.test` where a secondary placeholder is needed

The real portfolio URL is not committed. Future real runs must use local ignored input and explicit owner authorization.

## Engine Module Mapping

The shell mirrors existing engine modules:

- Policy and scope model: Target & Scope
- Safe HTTP/header checks: Operator Pipeline and Evidence
- Passive fingerprinting: Attack Surface
- Attack surface graph: Attack Surface
- Vulnerability intelligence: Operator Pipeline
- Safe recon planner: Recon Plan
- Green-tier tool capability suggestions: AI Guardrails and Recon Plan
- Remediation and retest: Remediation & Retest
- Approval queue: Approvals
- AI contracts and model router: AI Guardrails

All integration is visual and mock-only in this task.

## Tauri Security Posture

The Tauri config intentionally does not define sidecar execution, shell permissions, broad filesystem permissions, or provider/model access. The Rust entrypoint starts only the shell window.

Future Tauri-to-Python integration should use the existing engine JSON CLI/API contract, explicit command allowlists, safe-mode defaults, structured request/response validation, and audit/evidence hooks.

## Running The UI Later

If Node, Rust, and Tauri dependencies are installed:

```bash
cd apps/desktop
npm install
npm run dev
npm run tauri dev
```

The repository validation for TASK-024 does not require installing frontend dependencies.

Static shell validation:

```bash
cd apps/desktop
npm run check:shell
```

## Not Implemented Yet

- Live sidecar bridge
- Real project persistence UI
- Real report viewer from generated files
- Live model calls
- External tool execution
- Packaging or installer
