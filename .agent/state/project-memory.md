# Project Memory

## Product Identity

Aegis EV is a defensive, authorized Web/API exposure validation workbench.

## Current Phase

Phase 1 is Modern Web/API validation only.

## Non-Negotiable Rules

- No stealth.
- No ban bypass.
- No unauthorized scanning.
- No browser session scraping.
- No raw LLM shell execution.
- Policy before AI.
- No credential attacks, brute force, password spraying, or session hijacking.
- No direct push to `main`.
- No automatic merge into `beta`.
- Local development/testing uses account-authenticated Codex CLI and Gemini CLI, not API keys.
- API key/BYOK support is future production/customer-provider scope only.
- Never inspect or commit CLI auth files, browser/session credentials, cookies, tokens, keyrings, auth caches, or credential stores.

## Architecture Summary

Aegis EV uses a local-first architecture:

- Tauri UI.
- Python sidecar/control layer.
- Deterministic policy gateway.
- Policy-gated safe tool adapters.
- Evidence-backed findings.
- Provider-agnostic AI assistants outside trust boundaries.

## Branch Model

- `main` is stable and never pushed by agents.
- `beta` is the integration target and never auto-merged by agents.
- `feat/*` branches are the only branches agents may push to.
- QA branches may be used for review experiments, but QA output is advisory.

## Current Task

TASK-009 safe web header config checks.

## Open Decisions

- Whether the relay should later open draft PRs automatically with `gh`.
- Whether CI should be added as a separate task for `python3` engine tests.

## Latest Status

- TASK-001 repository hygiene and multi-agent workflow documentation were added.
- Local commands and prompt templates were standardized on `python3`.
- TASK-001C is adding a local file-based Codex/Gemini relay with repo memory and local CLI orchestration.
- TASK-002 hardens the deterministic policy core before additional AI or tool execution features.
- Policy decisions now emphasize explicit authorization windows, scoped targets, impact levels, approvals, budgets, and audit-safe serialization.
- TASK-003 hardens audit log durability with structured events, deterministic hashes, verification results, and secret redaction.
- TASK-004 adds a planning-only safe adapter framework with structured requests, registry, policy/audit integration, and no real scanner execution.
- TASK-004B records the project-wide local development/testing auth decision: use account-authenticated local Codex/Gemini CLIs, not API keys.
- TASK-005 adds evidence and finding models, deterministic evidence hashes, secret-safe serialization, conservative finding verification defaults, and in-memory/JSON/JSONL evidence store primitives.
- TASK-006 adds deterministic JSON and Markdown report generation from evidence, findings, audit verification metadata, and project scope without PDF, UI, AI prose, scanner integration, or network side effects.
- TASK-007 adds a deterministic JSON CLI/API contract for policy validation, dry-run adapter planning, report rendering, and audit verification for future Tauri sidecar integration.
- TASK-008 adds a local approval queue and HITL lifecycle for policy/adapters, plus approval-aware audit, evidence, and CLI contract commands.
- TASK-009 adds deterministic supplied-data web header and configuration analysis with secret-safe evidence, candidate findings, and no live network requests.
