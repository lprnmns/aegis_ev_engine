# Codex Task 00 — Bootstrap Review and Repository Hygiene

Read `AGENTS.md`, all files in `docs/`, and all ADRs. Then:

1. Summarize the product constraints in your own words.
2. Verify the repository layout.
3. Run the Python engine tests:

```bash
cd engine
PYTHONPATH=src python -m unittest discover -s tests
```

4. Do not change code unless a test or packaging issue prevents the bootstrap.
5. If you change anything, keep it minimal and explain the exact reason.
6. Do not push. Create a suggested commit message only.

Safety reminder: no stealth, no ban bypass, no session scraping, no raw shell execution by LLM.
