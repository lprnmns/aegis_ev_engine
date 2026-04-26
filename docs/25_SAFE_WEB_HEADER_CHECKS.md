# Safe Web Header and Configuration Checks

## Purpose

TASK-009 adds the first deterministic Web/API security check module for Aegis EV. It analyzes supplied HTTP response metadata such as headers, cookie attributes, protocol hints, and related configuration context without performing live network requests.

## What This Module Does

The module evaluates provided response and configuration data for common secure configuration gaps, including:

- Missing or weak `Content-Security-Policy`.
- Missing clickjacking protection through `X-Frame-Options` or CSP `frame-ancestors`.
- Missing or weak `Strict-Transport-Security` for HTTPS targets.
- Missing `X-Content-Type-Options: nosniff`.
- Missing or unsafe `Referrer-Policy`.
- Missing or permissive `Permissions-Policy`.
- Potentially unsafe supplied CORS configuration, including wildcard origins and wildcard or reflected origins combined with credentials.
- Cookie attribute gaps such as missing `Secure`, `HttpOnly`, or `SameSite`.
- Obvious server and framework disclosure headers.
- Cache-control gaps on sensitive-looking paths when that path is supplied.
- Optional `security.txt` presence only when the metadata explicitly says whether it was observed.

## What This Module Does Not Do

- It does not send HTTP requests.
- It does not crawl, fuzz, brute force, or scan.
- It does not integrate `httpx`, `katana`, `nuclei`, or other external tools.
- It does not confirm exploitability.
- It does not auto-verify or auto-confirm findings.
- It does not require API keys for local development or testing.

## Why No Live Network Scan Is Added

TASK-009 is intentionally constrained to supplied data only. That keeps the check layer deterministic, testable, authorization-safe, and reusable by future adapters that may fetch response metadata later under explicit policy control. The analysis logic is separated from transport so future authorized fetch adapters can reuse the same rules without changing the trust boundary.

## How Supplied Metadata Is Analyzed

The check module accepts structured input such as:

- `target`
- `normalized_target`
- `status_code`
- `headers`
- `content_type`
- `protocol`
- `tls_summary`
- `observed_redirects`
- `request_origin`
- `security_txt_present`

It normalizes header names, redacts sensitive values, and emits deterministic check results for observed configuration issues only.

## Severity and Confidence

Severity and confidence are deterministic:

- Missing CSP defaults to `medium`.
- Missing clickjacking protection is `medium` for HTML-like content and lower otherwise.
- Missing HSTS on HTTPS is `medium`.
- Wildcard CORS with credentials is `high`.
- Cookie attribute gaps are `medium` or `high` based on cookie context.
- Technology disclosure is `low` or `info`.
- Missing `nosniff`, `Referrer-Policy`, and `Permissions-Policy` stay `low` or `info`.

No AI model or external service influences severity.

## Evidence and Findings

Check results can be converted into:

- Evidence records with secret-safe structured data and redacted observations.
- Candidate findings with `verification_state = evidence_backed`.

Findings are not auto-confirmed. Header and configuration checks are observations about supplied metadata, not proof of successful exploitation.

## Adapter and CLI Integration

TASK-009 adds a safe planning adapter for supplied header analysis:

- Adapter ID: `web_header_config_check`
- Action: `analyze_headers`
- Default impact: `green`
- Network access: disabled
- Safe mode support: enabled

The engine CLI/API contract also exposes `analyze-web-headers`, which:

- Accepts JSON through stdin or `--input-file`
- Returns structured JSON
- Uses policy validation before analysis
- Produces deterministic evidence and candidate findings
- Does not perform live HTTP requests

## Redaction and Secret Safety

Before output is stored or returned, sensitive values are redacted:

- `Authorization` headers
- bearer tokens
- cookies
- `Set-Cookie` values
- session identifiers
- API keys
- passwords
- token-like values

Header names may remain visible when useful for explainability, but sensitive header values do not.

## Secure Configuration Framing

These checks map to OWASP-style secure configuration concerns such as security misconfiguration, information exposure, session security, and access control. They are intentionally conservative and explanatory so future authorized fetch adapters and report generation can reuse them without overstating risk.

## Future Use

Future authorized HTTP fetch or tool adapters may:

- collect response metadata under policy control
- pass that data into this deterministic check layer
- store the resulting evidence and candidate findings
- render the results through the reporting pipeline

That later transport work remains separate from TASK-009.
