# Local Agent Relay

## Purpose

The local relay coordinates Codex Builder and Gemini QA through repository files, local reports, Git branches, and locally installed CLIs. It is designed for a workflow where the user does not want to manually copy prompts between tools or manually run routine Git commands after every QA loop.

## Why Local Relay Instead of GitHub Actions

This repository uses local account-authenticated CLIs:

- `codex exec`
- `gemini -p`

The relay does not require `OPENAI_API_KEY`, `CODEX_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or GitHub Actions secrets. Authentication is handled only by already logged-in local CLI sessions.

GitHub Actions can be useful later for CI, but it is not the right default for this user workflow because it would require remote runners, secret configuration, and another operational surface. The local relay keeps coordination on the user's machine and inside the repository.

## Local Account Auth, Not API Keys

Local relay development and testing use already logged-in local CLIs:

- Codex CLI uses the user's local ChatGPT/Codex account session and plan limits.
- Gemini CLI uses the user's local Gemini account session and plan limits.

No `OPENAI_API_KEY`, `CODEX_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or GitHub Actions secret is required for local relay testing.

API key/BYOK support is future production/customer-provider scope only. It must be handled in a separate, explicitly scoped task with proper storage, redaction, and review.

GitHub Actions or other cloud runner modes must not receive personal account credentials or copied CLI session material. Never copy, inspect, print, modify, commit, or depend on auth files such as `~/.codex/`, `~/.gemini/`, browser cookies, session tokens, credential stores, keyrings, or auth caches.

## Single-Orchestrator Design

One local relay process owns the loop:

1. Rebuild context from repository files.
2. Ask Gemini QA for a verdict.
3. Ask Codex Builder to process QA feedback when needed.
4. Run validations.
5. Commit and push only the current feature branch.
6. Stop on `PASS`, max loops, blocked state, or an invalid verdict.

Two independent watchers are risky because they can race each other, overwrite reports, duplicate commits, push stale state, or create an uncontrolled agent loop. A single orchestrator gives one lock point, one loop counter, and one source of truth for the next actor.

## Repo Memory

Repo files are the long-term memory. Chat context is not required for task continuity.

Every non-interactive Codex/Gemini run must reconstruct project context from files:

- `AGENTS.md`
- `docs/`
- `adr/`
- `.agent/state/project-memory.md`
- `.agent/state/current-task.json`
- `.agent/reports/codex-builder-latest.md`
- `.agent/reports/gemini-qa-latest.md`
- Git diff against `beta`

This makes agent runs auditable and restartable even when chat history is unavailable.

## Branch Rules

- `main` is stable and must never be pushed by agents.
- `beta` is the integration target and must never be auto-merged by agents.
- `feat/*` branches are the only branches agents may push to.
- No force push.
- No history rewrite.

The user reviews the final PR and merges to `beta` only when satisfied.

## Loop Limits

The default max loop count is `3`. The relay must stop safely when the max loop count is reached or exceeded.

## Directories

Reports:

```text
.agent/reports/
```

State:

```text
.agent/state/
```

Prompts:

```text
.agent/prompts/codex/
.agent/prompts/gemini/
```

Most runtime state files should remain local and ignored. The tracked state files are:

- `.agent/state/README.md`
- `.agent/state/project-memory.md`
- `.agent/state/current-task.json`

## Required Local CLIs

Required:

- `codex`
- `gemini`
- `git`

Optional:

- `gh`

The relay must not ask for API keys. CLI authentication is assumed to come from already logged-in local sessions.

## Security Rules

- No credential file access.
- No secrets in logs.
- No browser/session scraping.
- No direct `main` push.
- No `beta` merge.
- No force push.
- No unsafe product feature changes.
- No stealth, ban bypass, proxy rotation for evasion, unauthorized scanning, credential attacks, or raw LLM shell execution behavior in product code.

The relay may call `codex exec` and `gemini -p` as local account-authenticated CLIs. It must not inspect, copy, print, commit, modify, or depend on auth files such as `~/.codex/`, `~/.gemini/`, browser cookies, tokens, credential stores, or keyrings.

## Human Role

The user:

- Starts and stops the relay.
- Reviews final reports and PR content.
- Merges to `beta` only when satisfied.

Agents may help prepare PR comment suggestions and push the current feature branch, but they do not own final integration.
