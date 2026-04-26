# Engine CLI API Contract

## Purpose

TASK-007 adds a deterministic CLI/API contract for the Python engine. Future Tauri sidecar calls, local automation, and integration tests can call stable engine commands and receive structured JSON responses without relying on human-oriented terminal output.

## Why JSON Is the Default Interface

JSON is parseable, deterministic, language-neutral, and easy for the Tauri UI to consume. Every machine command returns the same top-level response shape:

```json
{
  "ok": true,
  "command": "validate-policy",
  "result": {},
  "error": null,
  "warnings": [],
  "metadata": {
    "contract_version": "engine-cli.v1"
  }
}
```

Errors use:

```json
{
  "code": "invalid_json",
  "message": "Input was not valid JSON",
  "details": {}
}
```

## Tauri Sidecar Path

The Tauri UI can later invoke the Python sidecar with:

```bash
aegis-ev <command> --input-file request.json
```

or by writing JSON to stdin. Commands emit JSON to stdout and return a non-zero exit code when command processing fails.

## Safety Defaults

Commands are safe by default:

- No API keys are required for local development/testing.
- No network scanner execution.
- No PDF generation.
- No AI verifier or AI report writer.
- No raw shell execution.
- Adapter commands produce dry-run plans only.
- Report commands render deterministic JSON/Markdown only.
- Audit verification reads local JSONL audit files and sends nothing anywhere.

## Commands

### `validate-policy`

Validates a target/action against an authorization profile.

Input:

```json
{
  "target": "https://example.com",
  "impact": "green",
  "authorization_profile": {
    "owner": "customer/project",
    "allowed_domains": ["example.com"],
    "allowed_cidrs": [],
    "valid_from": "2026-01-01T00:00:00+00:00",
    "valid_until": "2026-01-02T00:00:00+00:00",
    "environment": "staging",
    "allowed_impact_levels": ["green"],
    "request_budget": {
      "max_requests": 10,
      "max_requests_per_minute": 30,
      "max_concurrency": 2
    }
  }
}
```

Output includes the policy decision, decision code, normalized target, and approval requirement.

### `plan-adapter`

Creates a dry-run adapter plan through the safe adapter framework. It does not execute scanners or make network calls.

Input includes `action_id`, `adapter_id`, `target`, `action`, `arguments`, `requested_impact_level`, `actor`, and `authorization_profile`.

### `render-report`

Renders deterministic Markdown or JSON reports from report metadata, evidence, findings, and optional audit verification metadata.

Input includes:

- `format`: `json` or `markdown`
- `report`: project/report metadata
- `evidence`: safe evidence records
- `findings`: finding records
- `audit_verification`: optional audit verification result

### `verify-audit`

Verifies a local audit JSONL hash chain.

Input:

```json
{
  "audit_log": ".aegis/audit.jsonl"
}
```

Missing files are handled safely and reported with a warning.

## Input Handling

Commands accept JSON by:

- `--input-file <path>`
- stdin when no input file is provided

Invalid JSON, missing input, missing required fields, unsupported commands, and unsupported report formats return structured errors. Normal CLI output does not print stack traces.

## Redaction

All command responses are passed through redaction before output. Responses must not print raw API keys, bearer tokens, cookies, authorization headers, passwords, session identifiers, browser/session artifacts, or credential material.

## Not Implemented Yet

- Tauri UI integration.
- PDF export.
- AI verifier.
- AI report writer.
- Real scanner execution.
- Production BYOK/provider mode.
- Database-backed command state.
