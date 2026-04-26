# Report Generation

## Purpose

TASK-006 adds the first deterministic report generation layer for Aegis EV. It renders evidence-backed project state into JSON and Markdown reports that can be reviewed, tested, diffed, and used later as input for PDF/export and UI report builder features.

## What It Does

- Builds structured report records from project metadata, findings, evidence summaries, and optional audit verification results.
- Renders stable JSON with schema version `report.v1`.
- Renders stable Markdown with metadata, scope, methodology, executive summary, risk summary, findings, evidence, audit summary, limitations, retest status, and a footer.
- Summarizes risk deterministically by severity, status, verification state, target, and category.
- Includes safe references to evidence and audit metadata without dumping raw request/response bodies or raw evidence payloads.
- Applies secret redaction before rendering report text.

## What It Does Not Do Yet

- No PDF generation.
- No report UI or report builder.
- No AI-generated prose.
- No AI verifier.
- No scanner output ingestion.
- No network calls.
- No external report storage.
- No customer branding system.

## Why Markdown and JSON Come Before PDF

Markdown and JSON are easier to test, review, diff, and validate than PDF. They provide deterministic intermediate formats that future PDF, UI, and customer-branded export layers can consume without changing the evidence or finding model.

## Why AI Prose Is Not Included Yet

AI prose generation is intentionally excluded from TASK-006. Reports must first preserve deterministic, evidence-backed structure. Future AI reporter features may draft wording, but AI text alone must not create or verify findings, override policy, or change recorded evidence.

## No Overclaiming

Reports must not claim that a finding is confirmed unless the finding record says it is `confirmed` or its verification state is `verified`. Candidate and draft findings are rendered as candidate or draft, with explicit status and verification state.

## Evidence Summary

Evidence summaries include only safe reference fields:

- Evidence ID.
- Evidence type and source type.
- Target and normalized target.
- Title and summary.
- Related audit event and adapter IDs.
- Confidence, redaction state, and tags.

Raw request/response content, scanner output, HAR content, screenshots, and arbitrary structured payloads are not dumped into reports in TASK-006.

## Audit Summary

Reports can include audit verification metadata:

- Total audit events.
- Verification result.
- Hash chain status.
- Latest event hash.
- Warning if verification is missing or failed.

Tamper-evident audit logging is not tamper-proof storage. Reports state this explicitly.

## Secret Redaction

Report generation redacts common secret-bearing text, including API keys, bearer tokens, cookies, authorization headers, passwords, session identifiers, and token-like values where practical. Redaction is applied before JSON or Markdown rendering.

## Future Path

Future tasks can build on this layer by adding:

- PDF rendering from deterministic JSON/Markdown.
- UI report builder.
- Customer branding.
- Report templates.
- AI-assisted wording that remains subordinate to evidence and verification state.
- Database-backed report persistence.
- Safe ingestion of real adapter output after scanner adapters exist.
