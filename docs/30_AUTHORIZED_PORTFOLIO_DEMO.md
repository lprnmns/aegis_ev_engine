# TASK-014 Authorized Portfolio Demo Harness

TASK-014 adds a local harness for the first future owner-authorized portfolio-site run. It composes the existing project/scope/session, policy, safe HTTP metadata fetch, header analysis, evidence, finding, audit, and report layers.

## What It Does

- Reads a local JSON input for one portfolio URL.
- Requires `owner_authorization_attestation: true`.
- Requires `safe_mode: true`.
- Requires the target host to match the supplied `allowed_domain`.
- Creates project, scope, target, and session records.
- Creates an authorization profile from the explicit scope.
- Runs one policy-gated `HEAD` metadata request through the TASK-013 safe fetcher.
- Analyzes returned headers with the deterministic web header checks.
- Creates evidence and candidate findings.
- Verifies the audit chain.
- Renders Markdown and JSON reports.

## What It Does Not Do

- It is not a scanner.
- It is not a crawler.
- It does not fuzz, brute force, or exploit.
- It does not use `nuclei`, `httpx`, `katana`, or external tools.
- It does not replay HAR.
- It does not run Postman collections.
- It does not capture login sessions.
- It does not store response bodies, cookies, tokens, or raw auth material.
- It does not require API keys.
- It does not hardcode the real portfolio URL.

## Local Input Convention

Real target details must be local-only:

```text
local/portfolio-demo-input.json
```

The `local/` directory is ignored by Git. Generated portfolio demo output is also ignored:

```text
output/portfolio-demo/
```

A commit-safe template is provided at:

```text
fixtures/demo/portfolio_demo_input.example.json
```

The template uses only:

```text
https://portfolio.example.test
```

## Required Attestation

The harness denies before transport unless the input includes:

```json
{
  "owner_authorization_attestation": true,
  "safe_mode": true
}
```

The target URL must match `allowed_domain`, and the scheme must be in `allowed_schemes`.

## Future Local Run

After the owner supplies their real URL in an ignored local file:

```bash
cd engine
PYTHONPATH=src python3 -m aegis_ev.main run-portfolio-demo --input-file ../local/portfolio-demo-input.json
```

Unit tests use fixture transports and perform no real network requests.

## Reports

The harness can return report contents in JSON or write:

- `portfolio_demo_report.md`
- `portfolio_demo_report.json`
- `audit.jsonl`

Reports state that this is an authorized owner-provided demo, that no crawling/fuzzing/scanning was performed, and that findings are candidate/evidence-backed observations, not confirmed exploitation.

## Safety Summary

- Policy is evaluated before transport.
- Redirects and timeouts are bounded.
- `HEAD` is used for the harness request.
- No request body or response body is stored.
- Raw request auth headers/cookies/tokens are not accepted.
- Sensitive response headers are redacted before evidence or reports.

## Not Implemented Yet

- UI.
- Authenticated testing.
- Login/session capture.
- Crawling.
- Fuzzing.
- External scanner integration.
- AI verifier.
- PDF export.
