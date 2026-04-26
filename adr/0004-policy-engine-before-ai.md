# ADR 0004 — Policy Engine Before AI

## Status

Accepted.

## Context

LLMs can hallucinate, misunderstand scope, or be influenced by prompt injection. They should not be trusted as enforcement mechanisms.

## Decision

The deterministic policy engine sits between AI and all execution. AI produces structured proposals; policy decides allow, deny, or require approval.

## Consequences

- More engineering work upfront.
- Much stronger safety model.
- Easier testing and auditability.
- Enterprise customers can review policy behavior.
