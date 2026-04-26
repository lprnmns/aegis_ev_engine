# Compliance and Legal Operating Model

## Authorized use only

Users must only test assets they own or are explicitly authorized to assess. The app should require a scope profile before any network interaction.

## Language policy

Avoid product language such as:

- stealth
- evasion
- ban bypass
- WAF bypass
- undetectable
- exploit everything

Use:

- authorized validation
- approved egress
- adaptive throttling
- production-safe request budget
- evidence-backed findings
- human-approved sensitive tests

## Data handling

- No secrets in source code.
- Sensitive headers are redacted in logs and reports.
- API keys must be stored in local secret storage in later versions.
- Reports should support customer-controlled export.

## AI provider policy

Use official APIs and officially supported coding tools only. Do not automate browser sessions, scrape private web sessions, or bypass provider rate limits.
