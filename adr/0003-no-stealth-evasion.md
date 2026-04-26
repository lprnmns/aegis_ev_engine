# ADR 0003 — No Stealth or Ban Evasion

## Status

Accepted.

## Context

Automatic IP rotation after blocks can look like unauthorized evasion. It increases legal, ethical, and enterprise trust risk.

## Decision

AegisEV will not implement autonomous ban bypass, stealth scanning, or automatic IP switching to continue after a block. It may support customer-approved egress profiles declared before a job.

## Consequences

- Safer B2B posture.
- Less abuse potential.
- Clearer audit story.
- WAF/rate-limit validation remains possible through approved, transparent scenarios.
