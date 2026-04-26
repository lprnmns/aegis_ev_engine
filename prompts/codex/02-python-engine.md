# Codex Task 02 — Engine CLI and Job Lifecycle

Goal: create a clean local engine interface that Tauri can later call.

Tasks:

1. Add a job lifecycle model: pending, running, completed, denied, failed, inconclusive.
2. Extend the CLI with:
   - `validate`,
   - `audit-verify`,
   - `policy-check`.
3. Ensure every command writes audit events.
4. Keep all target interaction behind policy checks.
5. Add integration tests using a local mock HTTP server only.
6. Run `PYTHONPATH=src python -m unittest discover -s tests`.

Do not perform internet scans in tests. Do not add raw shell execution.
