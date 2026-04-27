# Codex Report: TASK-016 Attack Surface Graph

## Summary

Implemented deterministic attack surface graph construction from supplied safe data.

The implementation adds:

- Attack surface graph node, edge, graph models.
- Stable node and edge IDs.
- Graph builder for projects, targets, endpoints, safe fetch metadata, header checks, technology fingerprints, evidence, and risk hypotheses.
- Deterministic risk summary and conservative priority hints.
- Evidence conversion and report-section helper.
- `AttackSurfaceGraphAdapter`.
- `build-attack-surface-graph` CLI/API command.
- Safe placeholder fixture and unit tests.

## Safety Posture

- No network behavior was added.
- No crawling, fuzzing, scanner integration, asset fetching, source map fetching, script execution, or external tool execution was added.
- No API keys are required for local development/testing.
- No real portfolio URL is committed.
- Graph hints are not vulnerability confirmation and no confirmed findings are created.

## Key Files

- `engine/src/aegis_ev/attack_surface.py`
- `engine/tests/test_attack_surface.py`
- `fixtures/demo/demo_attack_surface_input.json`
- `docs/32_ATTACK_SURFACE_GRAPH.md`
- `engine/src/aegis_ev/contracts.py`
- `engine/src/aegis_ev/adapters/framework.py`

## Validation

Passed locally:

- `./scripts/run_tests.sh` (`Ran 311 tests`)
- `cd engine && PYTHONPATH=src python3 -m unittest discover -s tests` (`Ran 311 tests`)
- `git diff --check`
- `python3 scripts/local_agent_relay.py --task-id TASK-016-attack-surface-graph --dry-run --once`
- `bash scripts/check_agent_relay_prereqs.sh`
- Provider config grep
- Real portfolio URL grep
