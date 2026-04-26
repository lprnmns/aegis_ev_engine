# Product Requirements Document — AegisEV v0.1

## 1. Overview

AegisEV is an AI-assisted desktop workbench for authorized Web/API exposure validation. It combines deterministic security checks, policy-gated tool orchestration, AI-assisted triage, evidence management, reporting, and retest workflows.

## 2. Problem

Security teams often receive noisy scanner output. Developers struggle to reproduce findings. Retesting after fixes is manual. Existing enterprise platforms are expensive and broad. AegisEV narrows the scope to modern Web/API systems and focuses on verified evidence.

## 3. Goals

- Provide a safe local-first desktop experience.
- Enforce scope and authorization before any target interaction.
- Run passive/low-impact checks by default.
- Collect normalized evidence for every finding.
- Use AI to explain, prioritize, and draft remediation, not to bypass controls.
- Support retest workflows.
- Produce professional reports for customers and engineering teams.

## 4. Non-goals for v0.1

- Android/iOS testing.
- Desktop binary analysis.
- Exploit development.
- Credential attacks.
- WAF bypass.
- Stealth or ban evasion.
- Automatic proxy switching after block responses.
- Raw shell execution by LLM agents.
- ChatGPT web session scraping.

## 5. User personas

### AppSec Lead

Needs defensible evidence, prioritization, and retest status.

### Pentest Consultant

Needs repeatable project setup, clean reports, and client-safe workflow.

### Developer / Tech Lead

Needs clear reproduction, impact, and actionable fix guidance.

## 6. Core user stories

1. As a user, I can define a target scope with domain allowlist and request budget.
2. As a user, I can import API context later from OpenAPI/Postman/HAR.
3. As a user, I can run a safe validation job.
4. As a user, I can see all tool actions in an audit log.
5. As a user, I can approve or reject sensitive actions.
6. As a user, I can inspect evidence behind every finding.
7. As a user, I can generate a Markdown/PDF report.
8. As a user, I can rerun validations after fixes.

## 7. Success metrics

- Confirmed-to-noise ratio.
- Time to first evidence-backed finding.
- Retest completion rate.
- User approval override rate.
- False positive rate from pilot feedback.
- Crash-free session rate.
- Average request budget usage per job.

## 8. MVP feature list

### Must-have

- Authorization profile.
- Policy engine.
- Safe HTTP security header check.
- Hash-chained audit log.
- Evidence model.
- Approval model.
- CLI entrypoint for engine tests.
- Documentation and Codex task prompts.

### Should-have

- Tauri UI shell.
- Local SQLite evidence store.
- Markdown report generator.
- OpenAPI endpoint inventory.
- Retest states.

### Could-have

- AI-assisted report wording.
- RAG references to OWASP/CWE/CVSS.
- Customer-branded reports.
- Team workspace sync.

## 9. Acceptance criteria for v0.1 engine skeleton

- `pytest` passes.
- Invalid target outside allowlist is rejected.
- Unsupported schemes are rejected.
- Audit log hash chain verifies.
- Safe header findings include evidence and severity hints.
- No network action runs without policy approval.
