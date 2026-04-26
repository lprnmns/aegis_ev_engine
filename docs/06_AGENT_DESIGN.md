# AI Agent Design

## Principle

AegisEV uses AI for planning, explanation, triage, and reporting. Deterministic policy code decides whether actions are allowed.

## Agents

### Planner

Input:

- Authorization profile.
- Target metadata.
- User-selected mode.
- Available adapters.

Output:

- Structured validation plan.
- No raw shell commands.

### Tool Router

Maps structured plan steps to adapter calls after policy checks.

### Verifier

Input:

- Normalized evidence.
- Tool output.
- Standards references.

Output:

- Finding candidate.
- Confidence level.
- Missing evidence list.

### Reporter

Creates human-readable reports using evidence and approved findings.

## Structured action schema

```json
{
  "action_type": "run_adapter",
  "adapter": "safe_headers",
  "target_id": "target_123",
  "impact": "green",
  "reason": "Check low-impact HTTP security headers",
  "requires_approval": false
}
```

## Prompt injection handling

Imported target content, HTTP responses, logs, and documents are untrusted. They may be summarized but never treated as instructions.

## Model provider policy

- Use official APIs or official Codex/IDE integrations only.
- No browser scraping or session cookie use.
- BYOK later with local secret storage and explicit redaction.
- Provider abstraction is mandatory.
