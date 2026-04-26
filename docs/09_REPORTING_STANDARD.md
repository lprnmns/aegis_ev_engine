# Reporting Standard

## Report sections

1. Executive summary.
2. Scope and authorization.
3. Methodology.
4. Guardrails and safety settings.
5. Asset inventory.
6. Findings overview.
7. Detailed findings.
8. Evidence appendix.
9. Remediation roadmap.
10. Retest results.
11. Audit summary.

## Finding fields

- Title.
- Severity.
- Confidence.
- Status: candidate / confirmed / false_positive / fixed / inconclusive.
- Affected asset.
- Evidence IDs.
- Reproduction summary.
- Business impact.
- Technical impact.
- CWE reference later.
- OWASP ASVS/API reference later.
- CVSS vector later.
- Remediation.
- Retest instructions.

## Evidence rules

A finding cannot be `confirmed` unless it has at least one normalized evidence object and a deterministic reason for the conclusion.

AI text may explain a finding, but AI text alone is never evidence.
