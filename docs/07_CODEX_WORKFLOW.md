# Codex Workflow

## Install Codex CLI

Use the official Codex CLI installation path in your own terminal. Sign in with your ChatGPT account or an API key. Do not paste tokens into this repository.

## Working model

Codex should work in small, reviewable tasks:

1. Read `AGENTS.md`.
2. Read relevant docs and ADRs.
3. Create a short plan.
4. Implement one coherent slice.
5. Run tests.
6. Summarize changes and risks.
7. Commit on a feature branch.
8. Open PR or let the repository owner push.

## Prompt sequence

Run prompts in this order:

1. `prompts/codex/00-bootstrap.md`
2. `prompts/codex/01-policy-core.md`
3. `prompts/codex/02-python-engine.md`
4. `prompts/codex/03-tauri-ui-shell.md`
5. `prompts/codex/04-reporting.md`
6. `prompts/codex/05-ci-cd.md`
7. `prompts/codex/06-safe-adapters.md`

## Safe GitHub authentication

Do not give Codex account passwords or long-lived broad tokens.

Preferred:

- Use GitHub CLI locally: `gh auth login`.
- Use fine-grained PAT only when necessary.
- Protect `main` branch.
- Enable push protection / secret scanning.
- Use pull requests.

## Branch discipline

```bash
git checkout -b feat/policy-core
cd engine
PYTHONPATH=src python -m unittest discover -s tests
git add .
git commit -m "feat(policy): add authorization profile validation"
```

Only the human repository owner should decide when to merge.
