# TASK-021 Remediation and Retest Workflow

## Purpose

The remediation and retest workflow turns candidate or evidence-backed findings into defensive guidance, safe retest plans, before/after comparisons, evidence, audit events, and report sections. It is designed to support fix verification without changing the target and without introducing scanners or intrusive validation.

## Remediation Guidance

Remediation guidance is deterministic and template-based. It uses the finding title, category, tags, evidence IDs, and optional technology fingerprint evidence to choose conservative defensive advice.

Supported header guidance includes:

- Content-Security-Policy
- X-Frame-Options and CSP `frame-ancestors`
- X-Content-Type-Options: `nosniff`
- Referrer-Policy
- Permissions-Policy
- Strict-Transport-Security when applicable
- Reduced technology disclosure through `Server` and `X-Powered-By`

Next.js and Vercel-oriented header guidance appears only when supplied fingerprint evidence supports those hints. Aegis EV does not modify source code, deployment settings, or the target site.

## Retest Workflow

A retest plan contains green-impact metadata/header comparison steps only. The workflow expects supplied observations or a future explicitly authorized safe metadata collection. It does not crawl, fuzz, run scanners, replay requests, or validate exploitability.

Retest outcomes are conservative:

- `appears_resolved`: the expected defensive observation is present in the after-state.
- `still_present`: the observation remains unchanged.
- `regressed`: reserved for future comparisons that detect a worse after-state.
- `inconclusive`: the comparison is ambiguous and requires human review.
- `not_retested`: no comparison was performed.

Findings are not deleted automatically. Candidate findings remain candidate unless a future workflow explicitly verifies and updates them with sufficient evidence.

## Before/After Comparison

The initial comparison engine covers safe header observations:

- Missing CSP appears resolved when `Content-Security-Policy` is present and non-empty.
- Missing clickjacking controls appear resolved when `X-Frame-Options` or CSP `frame-ancestors` is present.
- Missing `nosniff` appears resolved when `X-Content-Type-Options` equals `nosniff`.
- Missing Referrer-Policy, Permissions-Policy, or HSTS appears resolved when the relevant header is present.
- Technology disclosure appears resolved when disclosure headers are absent. Reduced disclosure remains inconclusive when human review is needed.

## Evidence, Audit, and Reports

The workflow creates redacted evidence for remediation guidance, retest plans, retest results, and before/after comparisons. Audit-safe events cover guidance creation, retest plan creation, retest execution lifecycle, inconclusive results, and finding retest status updates.

Report sections include:

- Remediation Guidance
- Retest Plan
- Retest Results
- Before/After Summary
- Remaining Work

Reports must avoid overclaiming. They use language such as `appears_resolved`, `still_present`, and `inconclusive`; they do not claim exploitability or full coverage.

## CLI Commands

The engine exposes JSON-in/JSON-out commands:

- `generate-remediation-guidance`
- `create-retest-plan`
- `compare-retest-results`

These commands require no API keys and perform no network access by default.

## Future Portfolio Retest

A future authorized portfolio retest can reuse the existing local ignored input pattern and policy-gated safe HTTP metadata fetch. The real portfolio URL must not be committed. Tests continue to use fixtures and fake data only.

## Not Implemented Yet

- Live automated retest command against the portfolio site
- External scanner retest
- AI-generated remediation
- UI remediation workflow
- Ticketing integration
