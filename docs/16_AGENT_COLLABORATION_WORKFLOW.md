# Agent Collaboration Workflow

## Purpose

This workflow keeps multi-agent development reviewable and aligned with the AegisEV safety model. Codex acts as Builder. Gemini acts as QA. Humans retain ownership of merges, scope decisions, and final acceptance.

## Branch Model

### `main`

`main` is the stable branch. Agents must not push directly to `main`. Only the repository owner may merge reviewed work into `main`.

### `beta`

`beta` is the integration branch for reviewed feature work. Feature branches should target `beta` unless the repository owner explicitly chooses another reviewed path.

### Feature Branches

Feature branches use short task names, for example:

```bash
git checkout -b feat/TASK-001-repo-hygiene
```

Codex Builder work happens on feature branches. Each feature branch should contain one coherent task with its implementation, tests, documentation, and handoff report.

### QA Branches

Gemini QA may review the feature branch directly or use a QA branch when it needs to test proposed changes in isolation. QA branches should be named with the task and review purpose, for example:

```text
qa/TASK-001-review
```

QA branches are for review notes, experiments, or suggested patches. They are not automatically accepted into feature branches.

## Roles

### Codex as Builder

Codex is responsible for:

- Reading `AGENTS.md`, relevant docs, and ADRs before making changes.
- Implementing the requested task only.
- Preserving the authorization-first scope model, Safe Mode defaults, policy gateway, immutable audit posture, and evidence-backed findings model.
- Keeping LLMs outside trust boundaries.
- Running the required tests before claiming completion.
- Producing a handoff report in `.agent/reports/`.

Codex must not implement unauthorized scanning, stealth, evasion, ban bypass, credential attacks, browser session scraping, raw LLM shell execution, or product features outside the task.

### Gemini as QA

Gemini is responsible for:

- Reviewing the feature branch against the task requirements, docs, ADRs, and safety guardrails.
- Checking for regressions, missing tests, unsafe behavior, unclear documentation, and scope creep.
- Providing evidence-backed findings with file paths and concrete reasoning.
- Distinguishing required fixes from optional suggestions.

Gemini QA does not approve merges by itself. QA output is advisory until reviewed by Codex Builder and the repository owner.

## Review Rules

- No direct push to `main`.
- No blind acceptance of QA suggestions.
- Every QA suggestion must be evaluated against product scope, safety posture, tests, and existing architecture.
- Security-sensitive changes require negative tests.
- Documentation-only tasks should not change runtime behavior.
- Unclear or conflicting QA feedback should be recorded as an open question instead of silently implemented.

## Required Handoff Report Format

Each Builder task must create a report at:

```text
.agent/reports/codex-<TASK-ID>.md
```

Use this format:

```markdown
# Codex Handoff Report: <TASK-ID>

## Summary

- <Brief statement of what changed.>

## Files Changed

- `<path>` - <reason>

## Tests Run

- `<command>` - <pass/fail and important notes>

## Security Posture

- <State whether authorization, Safe Mode, policy, audit, egress, and AI trust boundaries changed.>

## Risk

- <Residual risk, if any.>

## QA Focus

- <Specific areas Gemini should review.>

## Next Task Suggestion

- <One concrete next task.>
```

Reports must not contain secrets, API keys, customer credentials, cookies, or private tokens.
