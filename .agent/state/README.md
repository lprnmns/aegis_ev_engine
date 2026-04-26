# Agent State

This directory stores lightweight repo memory for stateless Codex and Gemini runs.

Runtime state files may be created locally for:

- Loop counters.
- Lock files.
- Last reviewed commit.
- Last actor.
- Next actor.
- Local relay status.

State files help non-interactive agent runs remember project context by reading the repository instead of relying on chat history.

Most runtime state files should be ignored. The tracked files are:

- `README.md`
- `project-memory.md`
- `current-task.json`

Do not store secrets, API keys, cookies, tokens, credential-store data, keyring data, or customer credentials in this directory.
