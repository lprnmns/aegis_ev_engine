# AGENTS.md — Operating Constitution for Codex and AI Coding Agents

This file is mandatory context for every Codex session in this repository.

## Mission

Build AegisEV as a professional, defensive, authorized exposure validation workbench. The first shippable product is Web/API-focused. The user experience must feel enterprise-grade, modern, safe, auditable, and calm.

## Absolute prohibitions

Do **not** implement, suggest, or enable:

1. Unauthorized scanning or testing.
2. Stealth, evasion, or ban-bypass behavior.
3. Automatic IP rotation to continue after a target blocks traffic.
4. Credential attacks, brute force, password spraying, or session hijacking.
5. Lateral movement, persistence, malware behavior, destructive payloads, or exploit chaining.
6. LLM-generated arbitrary shell commands executed without adapter-level policy validation.
7. Browser/session-token scraping of AI services.
8. Storage of GitHub tokens, OpenAI keys, cookies, customer secrets, or credentials in source code.
9. Direct push to `main` unless the repository owner explicitly does it locally after review.

## Local development authentication

Local development and testing use account-authenticated local CLIs:

- Codex CLI authenticated through the user's ChatGPT/Codex account and plan limits.
- Gemini CLI authenticated through the user's local Gemini account session.

Do not require `OPENAI_API_KEY`, `CODEX_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or GitHub Actions secrets for local relay, local QA, or local testing. API key/BYOK support is future production/customer-provider scope only and must be explicitly tasked.

Never inspect, copy, print, modify, commit, or depend on CLI auth files, browser/session credentials, cookies, tokens, keyrings, auth caches, or credential stores.

## Required design posture

Every change must preserve:

- Authorization-first scope model.
- Default Safe Mode.
- Tool permission matrix.
- Adaptive throttling that respects customer budget and `Retry-After`.
- Approved egress profiles only; no stealth proxy switching.
- Human approval for high-impact or ambiguous actions.
- Immutable audit log.
- Evidence-backed findings.
- Provider-agnostic AI layer.
- Tests before commit.

## Definition of done for every task

A Codex task is not done until:

1. Code compiles/runs locally.
2. Unit tests pass.
3. Public interfaces are typed and documented.
4. Security-sensitive behavior has negative tests.
5. No secrets are committed.
6. The change updates relevant docs/ADR if architecture changes.
7. The summary includes risk, tests run, and next task suggestion.

## Branching and Git behavior

Use feature branches:

```bash
git checkout -b feat/<short-task-name>
```

Run tests:

```bash
cd engine && pytest
```

Commit format:

```text
feat(policy): add authorization profile validation
fix(audit): make hash chain deterministic
docs(prd): clarify web/api phase scope
```

Do not auto-push to `main`. Prefer PRs.

## Engineering style

- Keep the policy engine deterministic.
- Keep LLMs outside trust boundaries.
- Tool adapters accept structured intents, not raw shell strings.
- Use allowlists, enums, typed models, and explicit failure modes.
- Favor boring, testable code over clever magic.
