# Codex Report: TASK-011 Project Target Scope Model

## Task

TASK-011-target-session-scope-project-model

## Branch

`feat/TASK-011-project-target-scope-model`

## Summary

Added the project workspace model layer for organizing authorized Web/API validation work before live testing exists.

## Implemented

- `ProjectRecord` with project status, scope, targets, linked imports/evidence/findings/reports, audit path, tags, and metadata.
- `TargetRecord` with target type, normalized value, environment, in-scope status, scope reason, and metadata.
- `ScopeDefinition` with allowlists, denylist, schemes, ports, validity window, owner attestation, and policy conversion.
- `SessionRecord` with selected targets and linked import/evidence/finding/approval/report IDs.
- `ProjectWorkspaceStore` with in-memory and JSON file-backed primitives.
- Policy validation helper for project targets.
- CLI/API contract commands for project, target, session, and reference workflows.
- Tests for validation, normalization, redaction, duplicate behavior, policy integration, CLI output, and no-network posture.

## Security Posture

- No live network requests.
- No website fetching.
- No HAR replay.
- No Postman execution.
- No scanner integration.
- No UI.
- No AI verifier.
- No API keys required for local development or testing.
- No browser cookies, bearer tokens, API keys, passwords, or raw auth/session material are stored.
- Project scope feeds policy and does not override policy denial.

## Portfolio Demo Readiness

The future portfolio demo is represented only with placeholder examples such as `https://portfolio.example.test`. The real URL is not hardcoded and no live request is made.

## Validation

Targeted tests passed during implementation:

```text
cd engine && PYTHONPATH=src python3 -m unittest tests.test_projects tests.test_cli_contracts
```

Full validation results are recorded in the final task response.
