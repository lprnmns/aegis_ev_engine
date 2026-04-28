# TASK-022 AI Planner, Verifier, and Reporter Contracts

## Purpose

The AI contract layer defines safe, provider-agnostic contracts for future Planner, Verifier, Reporter, Remediation Advisor, and Policy Reviewer roles. It prepares context packets, prompt templates, expected response schemas, validation rules, evidence helpers, and audit-safe events.

This task does not call any model. It does not require provider API keys. It does not execute tools.

## What It Does

- Defines static AI role contracts.
- Builds redacted context packets from existing engine outputs.
- Defines prompt templates with defensive-use instructions and JSON-only output requirements.
- Defines safe output schemas for planner, verifier, and reporter roles.
- Validates model-like outputs from fixtures or future callers.
- Rejects unsafe actions, unsupported claims, unknown evidence references, secret-like values, and overclaiming.
- Creates evidence and audit-safe events for prompt packet creation and output validation.
- Exposes JSON CLI/API commands for packet building and output validation.

## What It Does Not Do

- It does not invoke OpenAI, Gemini, NVIDIA, LiteLLM, or any provider API.
- It does not require API keys.
- It does not route models.
- It does not execute tools or raw shell commands.
- It does not approve its own actions.
- It does not crawl, fuzz, run scanners, or perform intrusive validation.
- It does not store chain-of-thought, raw response bodies, cookies, tokens, or auth headers.

## Role Contracts

- `planner`: proposes safe next steps from supplied graph, intelligence, evidence, findings, recon plans, and tool capabilities.
- `verifier`: reviews candidate findings against supplied evidence and records verification gaps.
- `reporter`: drafts report-safe summaries and limitations from supplied evidence.
- `remediation_advisor`: prepares defensive remediation language from supplied findings and remediation context.
- `policy_reviewer`: summarizes policy and approval implications without changing deterministic policy decisions.

## Context Packets

Context packets contain redacted summaries only:

- scope, policy, and authorization summaries
- attack surface and fingerprint summaries
- vulnerability intelligence and recon plan summaries
- evidence and finding summaries
- remediation and retest summaries
- tool capability summaries
- allowed and forbidden action sets
- safety constraints

Tracked fixtures use only `portfolio.example.test` and `api.portfolio.example.test`.

## Guardrail Validation

The validator checks:

- required fields
- role alignment
- evidence ID references
- forbidden actions
- amber/red approval requirements
- unsupported tool execution
- secret-like values
- unsafe terms
- candidate versus confirmed language consistency
- reporter overclaiming such as unsupported full-coverage statements

Failed validation returns structured errors. Validation evidence can be created without storing chain-of-thought.

## Human Approval Boundaries

AI output can request human review or mark approval-required steps. It cannot approve itself, override policy, or make red actions executable. Amber and red actions require human approval and deterministic policy handling in future execution layers.

## CLI Commands

- `build-ai-planner-packet`
- `validate-ai-planner-output`
- `build-ai-verifier-packet`
- `validate-ai-verifier-output`
- `build-ai-reporter-packet`
- `validate-ai-reporter-output`

All commands are JSON-in/JSON-out, require no API keys, make no network calls, and execute no tools.

## Future Provider Integration

Future provider integration can pass these packets to a provider router only after a separate task defines routing, credentials, privacy boundaries, logging rules, model invocation controls, and approval behavior. The deterministic validators remain the enforcement point for returned content.

## Not Implemented Yet

- Live model invocation
- Provider routing
- Autonomous tool execution
- Chain-of-thought storage
- AI verifier production mode
- UI
