# TASK-015 Passive Technology Fingerprinting

TASK-015 adds deterministic passive technology fingerprinting for supplied HTTP metadata, capped HTML snippets, asset path hints, and imported endpoint inventory.

## What It Does

- Detects conservative technology hints from supplied headers.
- Detects explicit frontend/build markers from a capped HTML snippet.
- Extracts script/link path hints without fetching assets.
- Summarizes supplied endpoint inventory into admin/API surface hints.
- Records security controls present or missing from supplied headers.
- Produces risk hypotheses for safe human review and future planning.
- Converts fingerprint results into evidence.
- Exposes a `fingerprint-technology` CLI/API command.

## What It Does Not Do

- It does not crawl.
- It does not fetch linked assets.
- It does not fetch source maps.
- It does not execute scripts.
- It does not run scanners or external tools.
- It does not fuzz, brute force, exploit, or validate vulnerabilities.
- It does not store full HTML or response bodies.
- It does not require API keys.
- It does not hardcode the real portfolio URL.

## Why Fingerprinting Is Not Confirmation

Fingerprints are inventory and prioritization signals. A header, asset path, or HTML marker can suggest a technology, but it does not prove exploitability or vulnerability. TASK-015 therefore produces technology hints and risk hypotheses, not confirmed findings.

Risk hypotheses use `status: hypothesis` and include a safe next step. They are separate from findings.

## Inputs

Fingerprinting accepts only supplied data:

- response headers
- final URL and redirect metadata
- content type and content length
- optional capped HTML snippet
- optional script/link path lists
- optional meta tags
- optional imported endpoint inventory
- evidence IDs from prior fetch/import/header observations

It can also consume a TASK-013 safe fetch result object. The fingerprint layer itself performs no network requests.

## Evidence

Fingerprint results become evidence with:

- `evidence_type: adapter_output`
- `source_type: technology_fingerprint`
- redacted structured data
- no full HTML
- no response body
- no cookies, tokens, or raw auth material

## Technology Categories

Detected technology entries may use categories such as:

- `frontend_framework`
- `backend_framework`
- `language`
- `cms`
- `cdn`
- `hosting`
- `web_server`
- `analytics`
- `security_control`
- `build_tool`
- `unknown`

Confidence is deterministic: `low`, `medium`, or `high`.

## Future AI Security Operator Path

This task supports the future authorized AI security operator by creating structured inventory. Future tasks can map fingerprints to CVE/KEV/EPSS/RAG data, generate candidate hypotheses, select safe tools, and validate only within authorization and policy scope.

## Portfolio Demo Path

The authorized portfolio demo can later call `fingerprint-technology` after the existing safe fetch/header analysis step. The real portfolio URL must remain in ignored local input/output only. Tests use fixtures and never contact the live site.

## Not Implemented Yet

- RAG/CVE/KEV/EPSS mapping.
- AI planner/verifier.
- Crawler.
- Scanner.
- Active validation recipes.
- UI.
- PDF export.
