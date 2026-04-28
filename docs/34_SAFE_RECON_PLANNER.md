# TASK-018 Safe Recon Planner

TASK-018 adds a deterministic safe reconnaissance planner. It converts supplied project, scope, attack surface graph, vulnerability intelligence, evidence, and candidate finding context into explainable next-step recommendations.

## What It Does

- Produces a structured `ReconPlan` with stable step IDs.
- Classifies steps as `green`, `amber`, or `red`.
- Recommends only existing safe adapters/actions for green planning steps.
- Applies policy decisions to each target-aware step.
- Marks approval-required steps without auto-approval.
- Blocks red or unknown-impact steps.
- Converts plans into evidence.
- Provides audit-safe planning events.
- Exposes a `plan-safe-recon` CLI/API command.

## What It Does Not Do

- It does not execute tools.
- It does not run scanners.
- It does not crawl.
- It does not fuzz.
- It does not validate vulnerabilities actively.
- It does not fetch live vulnerability feeds.
- It does not fetch assets or source maps.
- It does not execute scripts.
- It does not require API keys.
- It does not hardcode the real portfolio URL.

## Planning Is Separate From Execution

The planner creates recommendations only. Execution remains behind existing policy-gated adapters and future explicit tasks. This keeps future AI planner work outside the trust boundary: an AI can consume or explain a plan, but the deterministic policy and adapter layers still decide what can run.

## Impact Rules

Green steps include safe metadata fetch planning, supplied-header analysis, passive fingerprinting, attack surface graph construction, offline vulnerability intelligence mapping, evidence review, report generation, and retest planning.

Amber steps represent future actions such as authenticated validation, bounded discovery, endpoint confirmation, or higher-resource operations. TASK-018 records them as approval-required planning items only.

Red steps represent intrusive validation, brute force, fuzzing, exploit-style verification, credential/session manipulation, or similar unsafe operations. TASK-018 blocks them.

## Inputs

The planner accepts supplied safe data:

- attack surface graph
- vulnerability intelligence mapping
- passive technology fingerprint
- project/scope/target data
- evidence IDs and records
- candidate findings
- optional approval state
- adapter registry metadata

Invalid or missing optional context produces warnings or blocked steps rather than unsafe execution.

## Policy And Approval

Each target-aware step receives a policy decision. Out-of-scope targets are blocked. Production amber/red behavior remains approval-gated or blocked. The planner never approves its own recommendations.

## Evidence And Audit

Recon plans can become `recon_planner` evidence. Audit helpers produce events for:

- `recon_plan_created`
- `recon_step_proposed`
- `recon_step_blocked`
- `recon_step_requires_approval`

Events and evidence contain no secrets, no raw bodies, and no offensive reproduction content.

## Report Section

The report helper returns:

- Recon Plan Summary
- Proposed Safe Next Steps
- Blocked / Approval Required Steps
- Planning Rationale
- Limitations

## Future Portfolio Demo Path

The future authorized portfolio demo can use the planner after safe fetch, header checks, fingerprinting, graph construction, and vulnerability intelligence mapping. The real portfolio URL must remain in ignored local input/output and must not be committed.

## Not Implemented Yet

- Autonomous AI planner.
- Live tool execution.
- Active validation recipes.
- Green-tier external tool adapter pack.
- UI.
- Full retest workflow.
