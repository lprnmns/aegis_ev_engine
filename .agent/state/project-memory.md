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

TASK-004 safe tool adapter framework.

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
