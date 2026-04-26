# Codex Report: TASK-012 End-to-End Local Demo Flow

## Task

TASK-012-end-to-end-local-demo-flow

## Branch

`feat/TASK-012-end-to-end-local-demo-flow`

## Summary

Added a deterministic fixture-only local demo flow that proves the Aegis EV engine pipeline from project/scope setup through imports, header checks, evidence, candidate findings, audit verification, and Markdown/JSON reporting.

## Implemented

- Demo fixtures under `fixtures/demo/`.
- `engine/src/aegis_ev/demo_flow.py`.
- CLI/API command support for `run-demo-flow` and `demo-flow`.
- Markdown and JSON report generation from demo evidence/findings.
- Audit JSONL generation and verification.
- Tests for direct demo flow, CLI contract, deterministic output, redaction, no-network posture, and placeholder portfolio readiness.
- Documentation in `docs/28_END_TO_END_LOCAL_DEMO_FLOW.md`.

## Security Posture

- No live network requests.
- No website fetching.
- No scanner integration.
- No HAR replay.
- No Postman script execution.
- No crawling, fuzzing, brute force, nuclei, httpx, or katana integration.
- No UI, PDF, or AI verifier.
- No API keys required for local development or testing.
- No real portfolio URL is hardcoded.
- Fixture secrets are fake and are redacted in serialized demo output.

## Portfolio Demo Readiness

The flow models the future owner-authorized portfolio demo using only `https://portfolio.example.test` and `https://api.portfolio.example.test`. It performs no live request.

## Validation

Targeted tests passed during implementation:

```text
cd engine && PYTHONPATH=src python3 -m unittest tests.test_demo_flow tests.test_cli_contracts
```

Full validation results are recorded in the final task response.
