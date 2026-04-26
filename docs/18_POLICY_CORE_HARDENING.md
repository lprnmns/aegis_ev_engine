# Policy Core Hardening

## Purpose

The policy core is the deterministic gate that decides whether a proposed Aegis EV action is allowed, denied, or requires explicit human approval. It runs before AI planning, tool routing, adapters, or any target interaction.

## What It Does

- Validates authorization profiles.
- Normalizes target URLs before scope checks.
- Enforces domain and CIDR allowlists.
- Rejects unsupported schemes and out-of-scope targets.
- Applies impact-level rules for `green`, `amber`, and `red` actions.
- Applies approval requirements for red, authenticated, production amber, and budget-escalating actions.
- Enforces request budget decisions without performing network throttling.
- Produces structured, audit-safe decisions.

## What It Does Not Do

- It does not perform network requests.
- It does not scan targets.
- It does not throttle live traffic.
- It does not bypass blocks, rotate proxies, evade WAFs, or hide identity.
- It does not execute shell commands.
- It does not trust AI output as authorization.

## Why Policy Comes Before AI and Tool Execution

LLMs can hallucinate, misunderstand scope, or be influenced by untrusted target content. Aegis EV keeps AI outside the trust boundary. AI may propose structured actions later, but the policy core decides whether those actions are allowed, denied, or require approval before execution reaches any adapter.

## Default-Deny Behavior

The policy core fails closed. It denies when:

- Authorization is expired or not yet valid.
- Scope allowlists are empty.
- Target schemes are unsupported.
- Target hosts are out of scope.
- A host resembles an allowed domain but is not actually scoped.
- Impact level is unknown.
- Impact level is not allowed by the authorization profile.
- Request budget is exhausted.
- Authorization profile fields are missing or invalid.

## Impact Levels

- `green`: passive, read-only, low-impact validation.
- `amber`: authenticated or moderate validation that requires stricter review.
- `red`: intrusive or potentially state-changing validation that must never auto-run.

The authorization profile lists allowed impact levels. Unknown impact levels deny safely.

## Approval Rules

Explicit human approval is required for:

- Red impact actions.
- Authenticated actions when the profile requires it.
- Amber production actions when the profile requires it.
- Budget escalation above the authorized request budget.

Without explicit approval, these decisions are not allowed to execute. Policy decisions include `required_approval` and a decision code so approval queues and audit logs can explain why execution stopped.

## Budget Policy

The policy core validates request budget shape and enforces request-count decisions. It can deny exhausted budgets or require approval for budget escalation. Live network throttling and token-bucket scheduling are future adapter/scheduler responsibilities, not part of this policy-only task.

## Structured Decisions and Audit

Policy checks return structured decisions with:

- `allowed`
- `decision`
- `code`
- `reason`
- `message`
- `required_approval`
- `normalized_target`

Audit-safe serialization includes target, normalized target, action type, adapter, impact level, decision code, and approval requirement. Query strings, fragments, and URL credentials are stripped from serialized decision targets to reduce secret leakage risk.

## Future Adapter Preparation

Future safe tool adapters should accept only structured intents. They should call the policy core before any side effect, record the policy decision to the audit log, and execute only when `allowed` is true. This keeps AI planning, approval state, and tool execution separated by a deterministic control point.
