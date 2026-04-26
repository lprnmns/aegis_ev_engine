# TASK-010 API Import Foundation

TASK-010 adds a safe, JSON-first import foundation for user-provided API and application interface descriptions. It normalizes OpenAPI JSON, Postman collection JSON, and HAR JSON into endpoint inventory records that later validation workflows can use as authorized targets.

## What It Does

- Parses supplied OpenAPI 3.x JSON, with basic Swagger 2.0 path/method tolerance.
- Parses supplied Postman v2.1-style collection JSON, including nested item groups.
- Parses supplied HAR JSON request metadata.
- Produces deterministic endpoint inventory models with method, path, URL metadata, operation summaries, parameter summaries, auth indicators, sensitive indicators, and risk hints.
- Produces import result models with endpoint counts, warnings, errors, evidence IDs, and redaction status.
- Converts import results into secret-safe evidence records.
- Adds a planning-only `api_import` adapter for supplied JSON import actions.
- Adds CLI/API commands:
  - `import-openapi`
  - `import-postman`
  - `import-har`

## What It Does Not Do

- It does not fetch OpenAPI URLs or remote `$ref` values.
- It does not replay HAR requests.
- It does not run Postman collections, scripts, tests, or pre-request hooks.
- It does not crawl, fuzz, scan, brute force, or execute external tools.
- It does not create confirmed findings.
- It does not use AI verification or AI-generated conclusions.
- It does not require API keys or provider secrets for local development.

## JSON-First Support

TASK-010 intentionally supports JSON inputs only. YAML OpenAPI support can be added later if the project accepts a parser dependency or implements a constrained conversion path. Unsupported or malformed inputs return structured errors rather than stack traces.

## Endpoint Inventory

Each endpoint inventory record includes deterministic identifiers where practical:

- `endpoint_id`
- `source_type`
- `source_id`
- `method`
- `path`
- `url` and `normalized_url` when available
- `host` and `scheme` when available
- `operation_id`, `summary`, `description`, and `tags`
- `parameters_summary`, `request_body_summary`, and `response_summary`
- `auth_indicators`
- `sensitive_indicators`
- `risk_hints`
- `metadata`

Endpoint records are inventory, not vulnerability proof.

## Risk Hints

Imports may produce hints such as sensitive path indicators, missing auth indicators for sensitive-looking OpenAPI operations, or legacy-looking endpoint names. These hints are triage signals only. They are not confirmed findings and do not prove exploitability.

## Evidence

Import results can be converted into `adapter_output` evidence with `api_import` source type. Evidence stores only redacted structured summaries and endpoint metadata. Raw request bodies, cookies, authorization values, token values, and password-like values are not stored.

## Redaction

The import layer aligns with existing audit/evidence/report redaction. It redacts or avoids storing:

- Authorization headers and bearer tokens.
- API keys.
- Cookies and `Set-Cookie` values.
- Session identifiers.
- Passwords and secret-like values.
- Sensitive query string values.

Parameter names may remain when useful for inventory, but sensitive values are removed.

## Adapter and CLI Contract

The `api_import` adapter is green-impact, safe-mode compatible, and planning-only. It accepts supplied JSON data and rejects unsupported actions or invalid argument shapes. It does not perform network access.

The CLI/API contract commands return machine-readable JSON with the standard response shape:

- `ok`
- `command`
- `result`
- `error`
- `warnings`
- `metadata`

## Recovery Note

The first TASK-010 attempt was produced by a non-OpenAI provider and committed directly to `beta`. This GPT recovery branch reverts the untrusted implementation in branch history and replaces it with a reviewed implementation that preserves Aegis EV safety constraints.

## Future Path

Future tasks may use endpoint inventory for authorized Web/API validation, UI import flows, PDF/report builder output, or approved safe adapters. Those future layers must continue to avoid remote fetching, replay, or scanning unless a later task explicitly adds policy-gated authorized execution.
