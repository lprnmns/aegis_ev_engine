# AegisEV — AI-Assisted Authorized Exposure Validation Workbench

> Codename: **AegisEV**. Rename before public launch.

AegisEV is a desktop-first, policy-gated, AI-assisted security validation workbench for **authorized Web/API exposure validation**. It is not a stealth, evasion, or unauthorized access tool. The first production wedge is intentionally narrow: modern web applications and APIs with evidence-backed findings, human approval gates, adaptive throttling, audit logs, and retest workflows.

## Product thesis

Security teams do not need another noisy scanner. They need a safe way to answer:

- What is exposed?
- Which findings are evidence-backed?
- What is the business/technical impact?
- What should be fixed first?
- Did the fix actually work?

## Non-negotiable safety line

AegisEV will not implement autonomous ban bypass, stealth scanning, unauthorized proxy hopping, rate-limit circumvention, credential attacks, lateral movement, exploit chaining, or arbitrary shell execution by an LLM. All target interaction is bound by explicit authorization scope, a customer-approved request budget, tool permissions, and immutable audit logging.

## Phase 1 scope

Phase 1 is **Web/API only**:

- Scope editor and signed authorization profile.
- Passive/low-impact discovery.
- HTTP security header and configuration checks.
- OpenAPI/Postman/HAR import in later tasks.
- Evidence store.
- Human approval queue.
- Markdown/PDF report in later tasks.
- Retest workflow.

Mobile, iOS, Android, desktop binary analysis, fuzzing, and intrusive verification are deferred.

## Repository layout

```text
.
├── AGENTS.md                         # Codex/agent operating constitution
├── docs/                             # PRD, architecture, threat model, UX, roadmap
├── adr/                              # Architectural decision records
├── prompts/codex/                    # Codex task prompts, one part at a time
├── engine/                           # Python orchestration engine starter
├── .github/workflows/ci.yml          # CI for Python engine
├── scripts/                          # Local helper scripts
├── .env.example                      # Local env placeholder; never commit secrets
└── README.md
```

## Local engine quickstart

```bash
cd engine
python -m venv .venv
. .venv/bin/activate
PYTHONPATH=src python -m unittest discover -s tests
```

Example dry-run:

```bash
python -m aegis_ev.main validate --target https://example.com --allow-domain example.com
```

## Codex workflow

Start Codex at the repository root and feed it prompts from `prompts/codex/` sequentially. Do not skip tests. Do not allow Codex to commit secrets. Prefer pull requests over direct pushes to `main`.

```bash
codex
```

Inside Codex, paste one prompt at a time, starting with:

```text
Read AGENTS.md and docs/ first. Then execute prompts/codex/00-bootstrap.md exactly.
```
