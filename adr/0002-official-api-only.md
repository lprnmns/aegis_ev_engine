# ADR 0002 — Official AI Integrations Only

## Status

Accepted.

## Context

Browser session token scraping or unofficial automation is fragile, risky, and unsuitable for enterprise software.

## Decision

AegisEV will use official APIs, official Codex/IDE integrations, or documented provider SDKs only.

## Consequences

- Higher cost than session scraping.
- Enterprise credibility improves.
- Better reliability, security, and compliance posture.
- BYOK can be added with proper key storage and redaction.
