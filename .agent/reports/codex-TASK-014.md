# Codex Report: TASK-014 Authorized Portfolio Demo Harness

## Summary

Implemented the authorized portfolio demo harness for a future owner-provided portfolio-site run.

The harness:

- Uses ignored local input by convention.
- Requires explicit owner authorization attestation.
- Requires safe mode.
- Creates project, scope, target, and session state.
- Builds policy authorization from scope.
- Runs the TASK-013 safe HTTP metadata fetcher through an injectable transport.
- Feeds fetched headers into TASK-009 header checks.
- Creates evidence and candidate findings.
- Verifies audit.
- Renders Markdown and JSON reports.

## Safety Posture

- No real portfolio URL is committed.
- No live request is made in tests.
- No crawling, fuzzing, brute force, external scanner integration, HAR replay, or Postman execution was added.
- No authenticated login/session capture was added.
- No response body, cookies, tokens, or raw auth material is stored.
- No API keys are required for local development or testing.

## Key Files

- `engine/src/aegis_ev/portfolio_demo.py`
- `engine/tests/test_portfolio_demo.py`
- `fixtures/demo/portfolio_demo_input.example.json`
- `docs/30_AUTHORIZED_PORTFOLIO_DEMO.md`
- `.gitignore`

## Validation

Passed locally:

- `./scripts/run_tests.sh` (`Ran 266 tests`)
- `cd engine && PYTHONPATH=src python3 -m unittest discover -s tests` (`Ran 266 tests`)
- `git diff --check`
- `python3 scripts/local_agent_relay.py --task-id TASK-014-portfolio-demo-harness --dry-run --once`
- `bash scripts/check_agent_relay_prereqs.sh`
- Provider config grep
- Placeholder URL grep
