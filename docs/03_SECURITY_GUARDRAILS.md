# Security Guardrails

## Safety principle

AegisEV is a defensive validation tool. It must be difficult to misuse accidentally and unattractive to misuse intentionally.

## Guardrail stack

1. **Authorization profile** — explicit scope, owner, expiry, allowed domains/CIDRs.
2. **Safe Mode default** — low-impact checks only.
3. **Tool permission matrix** — adapters declare impact and capabilities.
4. **Budget enforcement** — max requests, concurrency, runtime, response size.
5. **Approval queue** — sensitive actions wait for human approval.
6. **Immutable audit log** — all actions and denials are hash-chained.
7. **Evidence normalization** — findings require reproducible evidence.
8. **Secret redaction** — logs and reports mask sensitive values.
9. **Kill switch** — user can stop a running job.
10. **No stealth** — no hidden evasion or unauthorized proxy rotation.

## Network behavior

Allowed:

- Respecting `Retry-After`.
- Slowing down when 429/503 responses appear.
- Stopping when error budgets are exceeded.
- Using customer-approved egress profiles declared before the job.

Disallowed:

- Switching IPs to bypass a block.
- Continuing after a block by hiding identity.
- Circumventing WAF/rate-limit defenses.
- Treating 403/1020 as a reason to evade.

## AI safety

- LLMs may recommend next steps.
- LLMs may summarize evidence.
- LLMs may draft remediation.
- LLMs may not execute raw commands.
- LLMs may not override policy decisions.

## Human approval triggers

- Any action classified as `amber` or `red`.
- Any operation above the default request budget.
- Any new egress profile.
- Any authenticated action.
- Any operation that could modify remote state.
- Any adapter with ambiguous impact.

## Production-safe defaults

```yaml
mode: safe
max_requests_per_minute: 30
max_concurrency: 2
max_runtime_seconds: 300
respect_retry_after: true
stop_on_block: true
require_approval_for_authenticated_checks: true
```
