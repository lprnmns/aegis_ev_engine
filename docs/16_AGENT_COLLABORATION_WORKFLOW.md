# Agent Collaboration Workflow

## Purpose

This workflow keeps multi-agent development reviewable and aligned with the AegisEV safety model. Codex acts as Builder. Gemini acts as QA. Humans retain ownership of merges, scope decisions, and final acceptance.

## Local Relay Mode

Local relay mode is preferred for this user's no-terminal copy/paste workflow. It coordinates Codex Builder and Gemini QA through tracked repo files, local reports, state files, local CLI calls, and feature-branch Git operations.

The relay uses account-authenticated local CLIs:

- `codex exec`
- `gemini -p`

GitHub Actions mode is optional and not required for this workflow. The local relay does not require OpenAI, Codex, Gemini, Google, or GitHub Actions API secrets.

Agents should not ask the user for OpenAI, Codex, Gemini, Google, or other AI provider API keys during local development, local relay runs, or local QA. The user's account-authenticated CLI sessions and plan limits apply.

API key/BYOK support is future production/customer-provider scope only. Any such work must be a separate, explicit task and must not be mixed into local relay/testing workflow tasks.

Repo memory is the source of truth. Chat memory is not required for task continuity because each non-interactive run rebuilds context from `AGENTS.md`, `docs/`, `adr/`, `.agent/state/`, latest reports, and the current Git diff.

The user still controls final review and merge. Agents may push only the current `feat/*` branch; they must not push `main`, merge `beta`, force push, or rewrite history.

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

## Commit Messages

Future commits should use:

```text
type(scope): message
```

Examples:

```text
chore(repo): add multi-agent workflow
docs(workflow): clarify qa handoff process
fix(tests): use python3 for local test runner
```

## Clipboard Handoff Convention

The source of truth for any next-agent prompt must always be a file, not only the clipboard.

Write next-agent prompts to:

```text
.agent/reports/next-prompt-<agent>-<TASK-ID>.txt
```

If a clipboard utility is available, agents may also copy the prompt to the clipboard. Clipboard availability must not be required for task success.

On Linux, accepted clipboard utilities include:

- `wl-copy`
- `xclip`
- `xsel`

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

## Next-Agent Prompt

- <Path to `.agent/reports/next-prompt-<agent>-<TASK-ID>.txt`, if follow-up QA or Builder work is needed.>
```

Reports must not contain secrets, API keys, customer credentials, cookies, or private tokens.
