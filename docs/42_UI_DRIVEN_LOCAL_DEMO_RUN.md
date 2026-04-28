# TASK-026 UI-Driven Local Demo Run

## Purpose

TASK-026 lets the desktop UI trigger the existing local fixture demo through the safe Tauri-to-Python bridge. The run is no-network, uses committed placeholder fixtures only, and updates the UI with structured project, pipeline, finding, evidence, audit, and report summaries.

## What It Does

- Adds UI state for a local demo run.
- Adds a `Run Local Demo` action that calls the allowlisted `run_local_demo_flow_no_network` bridge command.
- Normalizes the bridge response into UI summaries.
- Updates Overview, Target & Scope, Operator Pipeline, Findings, Evidence, and Reports views after a successful local demo run.
- Extends the Python demo result with redacted UI-friendly summaries.
- Keeps deterministic mock fallback when the Tauri runtime is unavailable.

## What It Does Not Do

- It does not run the live portfolio operator pipeline.
- It does not perform live HTTP fetches.
- It does not contact the real portfolio site.
- It does not run scanners, crawlers, fuzzers, or external tools.
- It does not call model providers.
- It does not require API keys.
- It does not open report files from disk.

## Bridge Command

The UI calls only:

```text
run_local_demo_flow_no_network
```

The command uses committed fixtures under `fixtures/demo/`, sets `no_network: true`, and returns explicit safety flags:

- `executed_live_network: false`
- `executed_external_tool: false`
- `executed_scanner: false`
- `executed_crawler: false`
- `executed_fuzzer: false`
- `called_model_provider: false`
- `required_api_key: false`
- `stored_raw_body: false`

## UI Rendering

The UI renders:

- Project summary.
- Target and scope summary.
- Pipeline stage summaries.
- Candidate finding summaries.
- Evidence summaries.
- Report summaries.
- Audit verification status.
- Warnings and errors.

Findings remain `candidate` and `evidence_backed`. The UI does not claim confirmed exploitability.

## Safety Posture

The UI clearly states:

- Local demo only.
- No live request.
- No real target.
- No scanner/crawler/fuzzer.
- No external tool execution.
- No model call.
- No API keys required.

Tracked UI data uses only placeholder domains such as `portfolio.example.test` and `api.portfolio.example.test`.

## Not Implemented Yet

- Live portfolio operator UI run.
- Project persistence from UI.
- Real report file opening.
- Provider settings.
- External tool execution.
- Packaging or installer.
