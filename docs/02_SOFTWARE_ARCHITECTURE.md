# Software Architecture

## Architecture style

AegisEV uses a local-first desktop architecture with a clear trust boundary between UI, policy, AI, and execution.

```text
Tauri UI
  -> Policy Gateway
      -> Job Scheduler
          -> Safe Tool Adapters
          -> Evidence Store
          -> Audit Log
      -> Approval Engine
      -> AI Assistants
          -> Planner
          -> Verifier
          -> Reporter
```

## Layers

### UI layer

- Tauri v2.
- React + TypeScript.
- TailwindCSS.
- Displays scope editor, approvals, job progress, evidence, and reports.

### Control layer

- Deterministic Python policy engine.
- Job scheduler.
- Approval state machine.
- Audit logger.

### AI layer

- Provider-agnostic model interface.
- Structured outputs only.
- No raw shell generation.
- Roles: Planner, Verifier, Reporter.

### Execution layer

- Tool adapters expose safe operations.
- Each adapter validates target, budget, args, and impact level.
- External CLI tools are introduced only behind adapters.

### Data layer

- Evidence objects.
- Findings.
- Audit events.
- Reports.
- Authorization profiles.

## Trust boundaries

The LLM is never trusted with direct execution. It can propose a structured action. The policy gateway decides whether the action is allowed, requires approval, or must be denied.

```text
LLM proposal -> structured intent -> policy gateway -> adapter -> evidence -> verifier -> report
```

## Error handling principles

- Fail closed.
- Prefer `denied` or `requires_approval` over implicit execution.
- Record all denials in the audit log.
- Keep user-facing errors clear and non-alarming.

## Scalability path

v0.1 is local. Later enterprise versions can add:

- Team workspaces.
- Central report storage.
- Signed policy bundles.
- Remote workers.
- SSO and RBAC.
- Organization-level audit export.
