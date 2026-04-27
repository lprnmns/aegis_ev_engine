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

TASK-014 authorized portfolio demo harness.

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
- TASK-010 was initially committed directly to `beta` by an untrusted non-OpenAI provider run. GPT recovery identified bad commit `789cdb400c90184505dc927848340f07f65e6996`, removed repository-local LiteLLM config, and rebuilt the API import foundation with safe OpenAPI/Postman/HAR parsing, endpoint inventory, evidence integration, adapter/CLI contract support, redaction, and no live network, HAR replay, Postman script execution, or confirmed findings.
- TASK-011 adds durable project, target, scope, session, and workspace store models with CLI/API contract commands, policy-backed scope validation, reference linking, portfolio-demo placeholder readiness, and no live network or secret/session material storage.
- TASK-012 adds a deterministic fixture-only local demo flow that creates project/scope/targets/session state, imports safe fixtures, analyzes supplied headers, creates evidence and candidate findings, verifies audit, and renders Markdown/JSON reports without contacting any live site.
- TASK-013 adds the first live-capable but conservative safe HTTP metadata fetch layer with policy-before-transport enforcement, HEAD/passive GET only, strict redirect/timeout controls, no body storage, audit/evidence/header-check integration, fake transport tests, and no crawler/fuzzer/scanner behavior.
- TASK-014 adds an authorized portfolio demo harness with ignored local input, required owner attestation, safe-mode gating, policy-scoped single-target metadata/header analysis, audit/evidence/candidate finding/report integration, and no real portfolio URL committed.
