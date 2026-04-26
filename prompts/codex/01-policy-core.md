# Codex Task 01 — Harden the Policy Core

Goal: make the policy engine robust enough to reject unsafe/out-of-scope actions before any network operation.

Tasks:

1. Read `docs/03_SECURITY_GUARDRAILS.md`, `docs/14_API_CONTRACTS.md`, and `adr/0004-policy-engine-before-ai.md`.
2. Improve `engine/src/aegis_ev/policy.py` if needed.
3. Add tests for:
   - unsupported scheme rejection,
   - subdomain allowlist behavior,
   - expired authorization profile,
   - request budget validation,
   - stop-on-block policy,
   - denial audit event creation if implemented.
4. Ensure the policy returns explicit `allow`, `deny`, or `requires_approval`.
5. Run `PYTHONPATH=src python -m unittest discover -s tests`.
6. Summarize changes and security impact.

Do not add intrusive tooling. Do not add proxy rotation. Do not add evasion behavior.
