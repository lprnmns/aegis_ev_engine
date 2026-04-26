# Audit Log Durability

## Purpose

The audit log records policy decisions and future tool execution events in an append-oriented, tamper-evident, secret-safe format. It gives users and reviewers an explainable record of what Aegis EV allowed, denied, or required approval for.

## Guarantees

- Audit records are written as JSONL for simple append behavior.
- Each record includes a deterministic hash over canonical event content.
- Each record includes the previous record hash, creating a hash chain.
- Verification detects malformed records, modified records, reordered records, and missing middle records where the chain no longer connects.
- Audit serialization redacts common secret-bearing fields before data is written.
- Policy decisions can be converted into audit events without network side effects.

## Non-Guarantees

- Tamper-evident does not mean tamper-proof.
- A local attacker with filesystem access can delete or replace the whole audit file.
- This does not provide signed remote attestation, WORM storage, or third-party timestamping.
- This does not provide database durability or multi-process locking.
- This does not inspect credential stores, browser sessions, keyrings, or token caches.

## Hash Chain

The first event uses `GENESIS` as `previous_hash`. Each later event stores the prior event's `event_hash`. The event hash is computed from deterministic JSON serialization of all event fields except `event_hash`.

Verification walks the file in order:

1. Parse each JSONL record.
2. Check required fields are present.
3. Confirm `previous_hash` matches the previous event.
4. Recompute `event_hash` from canonical content.
5. Return a structured result with `valid`, `event_count`, `last_hash`, and `errors`.

## Audit Event Fields

Audit events include:

- `event_id`
- `timestamp_utc`
- `actor`
- `event_type`
- `target`
- `normalized_target`
- `action`
- `impact_level`
- `decision_code`
- `allowed`
- `required_approval`
- `metadata`
- `previous_hash`
- `event_hash`

## Secret Redaction

Redaction runs before serialization. It redacts common secret-bearing keys and values, including:

- API keys.
- Bearer tokens.
- Cookies.
- Authorization headers.
- Session identifiers.
- Passwords.
- Generic token-like values where practical.

Target URLs are normalized for audit output by removing credentials, query strings, fragments, and token-like path segments.

## Policy Decisions

Policy decisions are logged through a dedicated helper that records:

- Target and normalized target.
- Action type.
- Adapter.
- Impact level.
- Decision code.
- Whether execution is allowed.
- Whether approval is required.

This preserves explainability without making policy more permissive or creating network side effects.

## Future Tool Adapters

Future adapters should append audit events for policy decisions, adapter start/stop events, denials, approval outcomes, and evidence references. They should keep raw secrets out of metadata and rely on the audit layer's redaction as a final safety net, not as the only protection.
