# Codex Report: TASK-023 Provider-Agnostic Model Router Stub

## Summary

Implemented the provider-agnostic model router stub. The engine now defines model provider profiles, routing policy, request/response envelopes, an offline deterministic mock provider, guardrail validation through TASK-022 validators, evidence/audit helpers, fixtures, tests, and CLI/API commands.

## Security Posture

- No live model calls were added.
- No provider API calls, API key requirements, browser/account-auth access, or provider config access were added.
- Only the mock provider is enabled for local tests.
- Account-auth and API-key provider profiles are disabled future metadata only.
- No autonomous tool execution, scanner, crawler, fuzzer, external tool execution, intrusive validation, or unsafe content was added.
- No real portfolio URL is committed.

## Files Added

- `engine/src/aegis_ev/model_router.py`
- `engine/tests/test_model_router.py`
- `fixtures/model_router/provider_profiles.json`
- `fixtures/model_router/routing_policy_mock_only.json`
- `fixtures/model_router/planner_request_input.json`
- `fixtures/model_router/mock_planner_response_valid.json`
- `fixtures/model_router/mock_planner_response_unsafe.json`
- `fixtures/model_router/mock_verifier_response_valid.json`
- `fixtures/model_router/mock_reporter_response_valid.json`
- `docs/39_PROVIDER_AGNOSTIC_MODEL_ROUTER.md`

## Files Updated

- `engine/src/aegis_ev/contracts.py`
- `engine/src/aegis_ev/evidence.py`
- `engine/src/aegis_ev/main.py`
- `.agent/state/current-task.json`
- `.agent/state/project-memory.md`
- `.agent/reports/codex-builder-latest.md`

## Validation

Passed:

- `./scripts/run_tests.sh`
- `cd engine && PYTHONPATH=src python3 -m unittest discover -s tests`
- `git diff --check`
- `python3 scripts/local_agent_relay.py --task-id TASK-023-provider-agnostic-model-router-stub --dry-run --once`
- `bash scripts/check_agent_relay_prereqs.sh`
- provider/local config grep (benign existing references only)
- real portfolio URL grep
- unsafe fixture/code language grep (existing TASK-022 forbidden-term blocklist only)
