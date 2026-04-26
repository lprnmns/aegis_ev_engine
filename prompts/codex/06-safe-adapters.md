# Codex Task 06 — Additional Safe Web/API Adapters

Goal: add only green-level Web/API adapters.

Allowed examples:

- HTTP header check.
- TLS metadata parser if local libraries support it.
- `security.txt` fetch with one request.
- robots.txt fetch with one request.
- OpenAPI document import from a local file.

Tasks:

1. Define adapter metadata for each adapter.
2. Enforce policy before network requests.
3. Respect budgets and stop conditions.
4. Add tests with local mock servers.
5. Normalize evidence.
6. Run `PYTHONPATH=src python -m unittest discover -s tests`.

Disallowed:

- fuzzing,
- brute force,
- directory busting,
- SQL injection tooling,
- WAF bypass,
- automatic proxy switching,
- high-volume scans.
