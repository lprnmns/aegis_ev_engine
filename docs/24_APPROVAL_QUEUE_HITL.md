# Approval Queue and Human in the Loop

## Purpose

TASK-008 adds the approval queue and human-in-the-loop model for Aegis EV. It gives the policy layer and adapter planning layer a deterministic way to stop higher-impact actions and require explicit, auditable human approval before those actions can proceed.

## Why Human Approval Exists

Aegis EV is designed to fail closed. Some actions must not move forward based only on policy evaluation, AI suggestion, or adapter intent. Human approval exists so that red-impact actions, authenticated checks, production amber actions, and budget escalations can be reviewed explicitly before execution would be allowed in future tasks.

## What Requires Approval

Approval is required when policy returns `requires_approval`, including:

- Red impact actions.
- Authenticated actions when the authorization profile requires approval.
- Amber production actions when the authorization profile requires approval.
- Budget escalations beyond the authorized request budget.

Missing approval must deny safely.

## Why LLMs Cannot Approve Their Own Actions

LLMs and agents remain outside the trust boundary. They may request work later through structured intents, but they must not approve their own requests. TASK-008 enforces that self-approval by agent/LLM requesters is denied, and approval/rejection actions are constrained to human actors in the current local model.

## Approval Lifecycle

Approval requests start in `pending` and may transition to:

- `approved`
- `rejected`
- `expired`
- `cancelled`
- `consumed`

Safe lifecycle rules:

- Only pending approvals may be approved, rejected, or cancelled.
- Only approved approvals may be consumed.
- Expired approvals cannot be approved or used.
- Consumed approvals cannot be reused.
- Approval IDs must remain unique.
- Decision events always record actor and timestamp.

## Scope Matching

Approvals must not broaden scope. A previously approved request only permits a blocked action if all relevant fields still match:

- Target.
- Normalized target.
- Action type.
- Impact level.
- Adapter ID when applicable.
- Adapter action when applicable.
- Required approval scope metadata.

If the approval does not match exactly, it is ignored and the original policy denial/approval requirement remains in effect.

## Integration Points

### Policy

Policy decisions that require approval can produce a structured `ApprovalRequest`. A matching approved request can later be applied back to a `ToolIntent` so policy can reevaluate the same action without broadening scope.

### Adapters

Dry-run adapter planning can now:

- Return that approval is required.
- Return an approval request when asked to create one.
- Accept a matching approved approval ID.
- Record approval status and approval ID in the returned plan.

No real tool execution is added in TASK-008.

### Audit

Approval lifecycle events are audit-safe and can be recorded as:

- `approval_requested`
- `approval_approved`
- `approval_rejected`
- `approval_expired`
- `approval_cancelled`
- `approval_consumed`

Audit metadata includes approval ID, action type, target, normalized target, impact level, status, actor, and decision reason without raw secrets.

### Evidence

Approval events can be converted into safe evidence records so future reports and UI flows can reference why an action was allowed, rejected, or consumed.

## CLI/API Contract

TASK-008 extends the engine CLI/API contract with JSON-first approval commands:

- `create-approval`
- `list-approvals`
- `approve-action`
- `reject-action`
- `consume-approval`
- `approval-status`

These commands:

- Read JSON from stdin or `--input-file`.
- Return structured JSON responses.
- Return non-zero on failure.
- Do not require API keys.
- Do not perform network activity.
- Do not run real tools.

## Not Implemented Yet

- Tauri approval UI.
- Real scanner execution.
- Notification system.
- RBAC or multi-user enterprise approval workflows.
- Production database persistence.
- Cross-machine approval coordination.
