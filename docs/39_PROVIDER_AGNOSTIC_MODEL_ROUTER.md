# TASK-023 Provider-Agnostic Model Router Stub

## Purpose

The provider-agnostic model router stub prepares Aegis EV for future AI model execution without calling any live provider. It defines provider profiles, routing policies, model request and response envelopes, a deterministic offline mock provider, guardrail validation hooks, evidence helpers, audit events, and CLI/API commands.

## What It Does

- Represents mock, account-auth CLI, API-key, local, proxy, and unknown provider types as metadata.
- Enables only the offline mock provider for local tests.
- Builds request envelopes from TASK-022 AI prompt packets.
- Produces deterministic mock planner, verifier, and reporter responses.
- Validates mock responses through TASK-022 guardrail validators.
- Produces redacted response envelopes, evidence, and audit-safe events.
- Exposes JSON CLI/API commands for provider listing, routing plans, mock execution, and response validation.

## What It Does Not Do

- It does not call OpenAI, Gemini, NVIDIA, LiteLLM, Anthropic, Ollama, or any provider API.
- It does not require API keys.
- It does not inspect local account-auth sessions, browser cookies, keyrings, tokens, or provider config files.
- It does not execute Codex, Gemini, local binaries, scanners, crawlers, fuzzers, or tools.
- It does not store chain-of-thought.
- It does not perform autonomous AI execution.

## Provider Profiles

The default profile set includes:

- `mock_safe_provider`: enabled, offline, deterministic, safe for local tests.
- `future_account_cli_provider`: disabled metadata for a future account-auth bridge.
- `future_api_provider`: disabled metadata for future BYOK/API-key production mode.

No profile contains credentials, user-specific config paths, or secret material.

## Routing Policy

The default routing policy is mock-only:

- default provider: `mock_safe_provider`
- API-key providers denied
- account-auth providers denied
- network providers denied
- structured output required
- guardrail validation required
- redaction required

Future tasks may add explicit provider routing only after defining credential handling, privacy boundaries, approval behavior, and operational controls.

## Request And Response Envelopes

Request envelopes include role, contract ID, context packet ID, selected provider, prompt packet, response schema, and safety constraints. They are serializable and redacted.

Response envelopes include parsed response, validation status, guardrail actions, human-review flag, and evidence IDs. Raw responses are optional and are not stored by default. Chain-of-thought is not stored.

## Guardrail Validation

Mock outputs are validated through TASK-022 planner, verifier, and reporter validators. Unsafe mock output is blocked and returned with explicit validation errors. The router does not trust model-like output until deterministic validation passes.

## CLI Commands

- `list-model-providers`
- `build-model-request-envelope`
- `route-model-request`
- `execute-mock-model-request`
- `validate-model-response-envelope`

All commands are JSON-in/JSON-out, require no API keys, make no network calls, access no account-auth sessions, and execute no tools.

## Future Work

- Live provider invocation
- Codex/Gemini account-auth bridge
- BYOK/API-key production provider mode
- Model streaming
- Autonomous tool execution
- UI model settings
