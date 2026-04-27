# TASK-013 Safe HTTP Metadata Fetch

TASK-013 adds the first conservative live-capable HTTP collection layer for Aegis EV. It is a policy-gated metadata fetcher designed to collect response headers and basic response metadata from explicitly scoped targets.

## What It Does

- Validates the target through the existing policy engine before any request.
- Supports only `HEAD` and passive `GET`.
- Defaults to `HEAD`.
- Uses strict timeout and redirect limits.
- Collects status code, final URL, redirect metadata, headers, content type, content length, elapsed time, and an HTTPS indicator from the URL.
- Stores no response body.
- Persists no cookies.
- Accepts no caller-supplied raw auth headers.
- Redacts sensitive response headers such as `Authorization`, `Cookie`, `Set-Cookie`, token-like headers, session-like headers, and API-key-like headers.
- Converts successful fetch metadata into evidence.
- Feeds fetched headers into the existing safe Web header/config analysis pipeline.
- Produces candidate/evidence-backed findings only.
- Writes audit-safe events for requested, denied, completed, and failed fetch attempts.

## What It Does Not Do

- It is not a scanner.
- It is not a crawler.
- It is not a fuzzer.
- It does not brute force.
- It does not integrate `nuclei`, `httpx`, `katana`, or other external scanners.
- It does not replay HAR.
- It does not run Postman collections.
- It does not capture login sessions.
- It does not store response bodies by default.
- It does not follow unlimited redirects.
- It does not require API keys.
- It does not hardcode the real portfolio URL.

## Why Policy-Gated

This is the first live-capable network layer, so policy is the trust boundary. The fetcher validates the target against an `AuthorizationProfile` before transport is invoked. Out-of-scope, unsupported scheme, expired authorization, exhausted budget, or approval-required decisions deny safely before the network transport runs.

Project scope can feed policy through the TASK-011 model, but project scope does not bypass policy.

## Safety Defaults

- Methods: `HEAD` by default; `GET` allowed only for passive metadata collection.
- Schemes: `http` and `https` only.
- Redirects: capped, default `3`.
- Timeout: small default, `5` seconds.
- Request budget: one request per adapter plan.
- Request headers: internal safe `User-Agent` only.
- Body: not read or stored by the model.
- Retries and parallel fetches: not implemented in TASK-013.

## Header Analysis Flow

The safe flow is:

1. Validate target with policy.
2. Fetch response metadata.
3. Redact sensitive headers.
4. Convert fetch result into evidence.
5. Analyze redacted headers with the deterministic Web header/config checks.
6. Convert significant checks into evidence and candidate findings.

Findings are not confirmed by default and do not claim exploitability.

## Audit Events

The fetcher can write audit-safe events:

- `http_fetch_requested`
- `http_fetch_denied`
- `http_fetch_completed`
- `http_fetch_failed`

Events include target, normalized target, method, status code when available, decision code, allowed state, redaction status, and `no_body_stored`. They do not include raw cookies, auth headers, or secrets.

## CLI/API Commands

TASK-013 adds:

- `fetch-http-metadata`
- `fetch-and-analyze-headers`

Both commands accept JSON via stdin or `--input-file` and return structured JSON. Unit tests use fixture transports and perform no real network calls.

## Portfolio Demo Readiness

A future authorized portfolio-site demo can use this layer only after the owner supplies the real portfolio URL and creates a matching project scope/authorization profile. The fetch will run only if the URL is allowlisted and policy allows it.

TASK-013 docs and tests use placeholders only, such as `https://portfolio.example.test`. No real portfolio URL is hardcoded and this task does not run against any live website.

## Not Implemented Yet

- Crawling.
- Login/session capture.
- Authenticated testing.
- WAF/rate-limit validation.
- External scanner integration.
- UI.
- PDF reporting.
- AI verifier.
