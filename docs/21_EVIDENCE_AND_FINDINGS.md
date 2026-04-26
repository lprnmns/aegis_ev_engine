# Evidence and Findings

## Purpose

The evidence and finding layer normalizes policy decisions, audit events, adapter plans, future adapter outputs, and future verifier results into reviewable records. It is the bridge between low-level system events and user-facing security findings.

TASK-005 adds models and storage primitives only. It does not add report generation, scanner ingestion, UI workflows, network activity, or AI verification.

## Evidence

Evidence is a structured, redacted record of something Aegis EV observed or decided. Evidence records include:

- Stable identifiers and UTC timestamps.
- Evidence type and source type.
- Target and normalized target when applicable.
- Human-readable title and summary.
- Redacted raw references and structured data.
- Related audit event or adapter identifiers.
- Tags, confidence, and a deterministic evidence hash.

Evidence types include policy decisions, adapter plans, adapter outputs, audit events, manual notes, screenshot references, request/response references, and unknown records. The initial implementation uses deterministic JSON serialization so record hashes are stable for the same content.

## Findings

A finding is a security issue candidate assembled from one or more evidence records. Findings include severity, confidence, status, target, category, optional CWE/OWASP/CVSS fields, evidence links, remediation, retest status, verification state, and tags.

New findings default conservatively. They do not default to `confirmed`, and future AI-generated findings must not be marked verified automatically.

## Candidate vs. Confirmed

`candidate` means the finding has enough structure to review but is not final. `confirmed` means the finding has explicit supporting evidence and has passed the required review path.

Low-confidence evidence creates draft or human-review-required findings. Critical or high-severity findings are not auto-confirmed simply because evidence exists.

## AI Output

AI output alone is not a verified finding. Future AI verifier output may become evidence, but verification state must still be controlled by deterministic policy, evidence links, and explicit review rules. This preserves the rule that LLMs remain outside Aegis EV trust boundaries.

## Evidence Links

Evidence can be created from:

- Policy decision objects.
- Audit events.
- Adapter plans.

These helpers preserve explainability by carrying decision code, target, normalized target, action, impact level, approval requirement, and sanitized arguments where applicable. Evidence records can then be linked to findings by evidence ID.

## Secret Redaction

Evidence and findings reuse the audit redaction layer. Redaction applies before serialization and hashing for common secret-bearing fields and values, including authorization headers, bearer tokens, cookies, session identifiers, API keys, passwords, and token-like values.

Raw credential material must not be stored as evidence. Screenshot, HAR, request/response, and adapter-output ingestion must continue to redact before persistence when implemented later.

## Store Behavior

The initial store is in-memory with optional JSON and JSONL export/import. It supports:

- Add/get/list evidence.
- Add/get/list findings.
- Duplicate ID rejection.
- Safe evidence-to-finding linking.
- Finding status updates with validation.

No database dependency is introduced in TASK-005.

## Not Implemented Yet

- Full report generation.
- AI verifier.
- Database persistence.
- Screenshot or HAR binary storage.
- Real scanner output ingestion.
- Real network tool integration.
- UI finding workflows.
