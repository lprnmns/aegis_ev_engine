# TASK-012 End-to-End Local Demo Flow

TASK-012 adds the first deterministic local demo flow for Aegis EV. The flow stitches together the existing safe engine components without making any live network requests.

## What The Demo Proves

The demo proves that the local engine pipeline can:

- Create a project, scope, targets, and session.
- Import supplied OpenAPI, Postman, and HAR fixture data.
- Analyze supplied HTTP header metadata.
- Convert imports and header observations into evidence.
- Convert significant header observations into candidate findings.
- Append and verify a tamper-evident audit chain.
- Generate deterministic Markdown and JSON reports.
- Return a machine-readable CLI/API result.

## What The Demo Does Not Prove

The demo does not prove live exposure, reachability, exploitability, or vulnerability confirmation. It does not contact any website, run scanners, replay requests, execute Postman scripts, crawl, fuzz, or use AI verification.

## Why Fixtures

Fixtures let the engine prove end-to-end data flow while preserving the safety posture. TASK-012 uses only placeholder reserved/example domains:

- `portfolio.example.test`
- `api.portfolio.example.test`

Fixture values that look like tokens or sessions are fake and are included only to verify redaction.

## Portfolio Demo Readiness

The future live demo will be authorized by the owner and aimed at the user's personal portfolio site. TASK-012 does not hardcode or contact the real portfolio URL. It models the future shape with placeholder targets only.

## How To Run

From the repository root:

```bash
cd engine
PYTHONPATH=src python3 -m aegis_ev.main run-demo-flow --input-file ../fixtures/demo/demo_flow_input.json
```

The CLI emits JSON with the standard engine contract response shape.

## Outputs

By default, report contents are returned in the JSON response and generated files are not committed. If `write_outputs` is true, the demo can write:

- `demo_report.md`
- `demo_report.json`
- `audit.jsonl`

Generated output is intended for local use and `output/demo/` is ignored by Git.

## Evidence, Findings, Reports, and Audit

OpenAPI/Postman/HAR imports become `api_import` evidence. Header/config observations become `web_header_check` evidence. Candidate findings link back to evidence IDs and are rendered into the Markdown/JSON reports. The audit chain records major local steps and is verified before the final demo result is returned.

Findings are candidate/evidence-backed by default. They are not confirmed and do not claim exploitability.

## No API Keys

The demo uses deterministic local code and fixture data. It does not require OpenAI, Gemini, NVIDIA, or other API keys.

## Not Implemented Yet

- Live HTTP runner.
- Real portfolio URL configuration.
- Scanner execution.
- HAR replay.
- Postman execution.
- UI.
- PDF generation.
- AI verifier.
