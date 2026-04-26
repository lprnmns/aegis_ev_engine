# Safe Tool Adapter Framework

## Purpose

Safe tool adapters are the only approved boundary for future tool execution in Aegis EV. They convert structured tool action requests into policy-gated, auditable, deterministic plans. TASK-004 adds the framework only; it does not add real scanner integrations or network execution.

## Why Adapters Exist

Adapters keep execution boring, reviewable, and testable:

- Inputs are structured requests, not shell strings.
- Adapter metadata declares capabilities, impact, authentication, network behavior, budgets, and evidence behavior.
- The policy core decides whether a request is allowed, denied, or requires approval before a plan can be considered executable.
- Audit logs record adapter planning decisions, including denied requests.

## Why LLMs Cannot Run Raw Shell Commands

LLMs are outside the trust boundary. They may propose structured actions in future tasks, but they must not execute commands or construct arbitrary shell strings. The adapter framework accepts structured requests only and uses deterministic adapter code to create safe previews. No `shell=True` execution path is introduced.

## Request Flow

1. A caller creates a `ToolActionRequest`.
2. The registry resolves a known, enabled adapter.
3. The planner creates a `ToolIntent` and sends it through the policy core.
4. Denied policy decisions produce denied plans and audit events.
5. Allowed policy decisions proceed to adapter action and argument validation.
6. The adapter returns a dry-run plan with sanitized arguments and deterministic preview data.
7. The audit log records the plan outcome.

## Audit Logging

Adapter plans can append audit-safe events with:

- `adapter_id`
- `action`
- target and normalized target
- impact level
- allowed/denied status
- decision code
- approval requirement
- sanitized arguments
- dry-run flag

Secrets are redacted by the audit layer before serialization.

## Example Adapter

TASK-004 adds `EchoPlanAdapter`, a harmless planning adapter used only for tests and framework demonstration. It does not scan, connect to targets, execute subprocesses, or produce evidence.

## Future Tool Integration

Future tools such as `httpx`, `katana`, or `nuclei` must be integrated behind adapters that:

- Declare metadata and supported actions.
- Accept typed structured arguments.
- Validate impact level and budgets.
- Pass through policy before any side effect.
- Use argv-list execution if execution is later added.
- Avoid `shell=True`.
- Enforce timeouts, output caps, safe working directories, and sanitized environments.
- Record policy and adapter decisions to the audit log.

## What This Does Not Do Yet

- No real scanning.
- No network crawling.
- No exploit or payload execution.
- No subprocess execution wrapper.
- No shell command execution.
- No proxy or egress switching.
- No AI-driven execution.

The framework prepares those future integrations to be policy-gated and auditable without adding unsafe capability in this task.
