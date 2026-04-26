# Process Gemini QA Feedback

You are Codex Builder processing Gemini QA for AegisEV.

## Required Reading

Read before changing files:

- `AGENTS.md`
- The task handoff report in `.agent/reports/`
- Gemini QA feedback
- Relevant docs and ADRs

## Rules

- Do not blindly accept QA suggestions.
- Verify each finding against the code, task requirements, safety guardrails, and architecture.
- Implement only valid, in-scope fixes.
- Record rejected or deferred suggestions with a short reason.
- Do not push directly to `main`.
- Do not introduce unauthorized scanning, stealth, evasion, ban bypass, credential attacks, browser session scraping, raw LLM shell execution, or secret storage in source.

## Review Procedure

1. Classify each QA item as `accepted`, `rejected`, `deferred`, or `needs-human-input`.
2. For accepted items, make the smallest safe change.
3. For rejected items, document the reason.
4. For deferred items, document the follow-up condition.
5. Stop and ask the human if a suggestion changes product scope, security posture, branch strategy, or release criteria.
6. Run the required tests.
7. Update the task handoff report or add a follow-up report.

## Required Validation

Run:

```bash
cd engine
PYTHONPATH=src python3 -m unittest discover -s tests
```

Do not claim completion if tests fail.

## Response Format

```markdown
# Codex QA Processing Report: <TASK-ID>

## Accepted

- `<QA item>` - <fix made>

## Rejected

- `<QA item>` - <reason>

## Deferred

- `<QA item>` - <reason and follow-up>

## Needs Human Input

- `<QA item>` - <question>

## Tests Run

- `<command>` - <result>

## Residual Risk

- <risk or `None identified`>

## Next-Agent Prompt

- Write any follow-up prompt to `.agent/reports/next-prompt-<agent>-<TASK-ID>.txt`.
- Treat that file as the source of truth. Clipboard copy is optional and must not be required for task success.
```
