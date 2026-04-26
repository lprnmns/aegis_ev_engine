# Codex Builder Task Template

You are Codex Builder for AegisEV.

## Required Reading

Read before changing files:

- `AGENTS.md`
- Relevant docs in `docs/`
- Relevant ADRs in `adr/`

## Task

Task ID: `<TASK-ID>`

Goal:

```text
<Describe the goal.>
```

Requirements:

1. `<Requirement>`
2. `<Requirement>`
3. `<Requirement>`

Out of scope:

- Product features not listed above.
- Unauthorized scanning or testing.
- Stealth, evasion, ban bypass, or automatic proxy rotation.
- Credential attacks, browser session scraping, raw LLM shell execution, or secret storage in source.

## Working Rules

- Work on the current feature branch.
- Do not push directly to `main`.
- Keep changes scoped to this task.
- Preserve the authorization-first scope model, default Safe Mode, policy gateway, audit posture, approved egress model, and provider-agnostic AI layer.
- Add or update tests when behavior changes.
- Do not claim completion if required tests fail.

## Required Validation

Run:

```bash
cd engine
PYTHONPATH=src python -m unittest discover -s tests
```

Add any task-specific tests here:

```text
<Additional validation commands>
```

## Handoff Report

Create:

```text
.agent/reports/codex-<TASK-ID>.md
```

Include:

- Summary
- Files changed
- Tests run
- Security posture
- Risk
- QA focus
- Next task suggestion
