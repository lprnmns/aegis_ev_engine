# Safe Tool Adapter Specification

## Purpose

Adapters convert safe, structured intents into deterministic actions. They are the only place where external tools or network actions may occur.

## Adapter metadata

Every adapter must declare:

- Name.
- Impact level: green / amber / red.
- Network behavior.
- Max default requests.
- Whether authentication is required.
- Whether approval is required.
- Allowed schemes.
- Output parser.
- Evidence types.

## Impact levels

### Green

Passive or low-impact checks. Example: one HTTP request for headers.

### Amber

Authenticated, repeated, or moderately intrusive checks. Requires approval.

### Red

Potentially destructive, state-changing, exploit-like, or high-volume actions. Disabled by default and out of scope for v0.1.

## Stop conditions

Adapters must stop on:

- Out-of-scope redirect.
- Request budget exceeded.
- 429 with Retry-After beyond budget.
- 403/block response when `stop_on_block` is true.
- User kill-switch.
- Runtime timeout.

## Proxy/egress rule

Adapters may use a preconfigured, customer-approved egress profile. They must not switch egress automatically to bypass blocks.
