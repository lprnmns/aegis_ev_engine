# Test Strategy

## Test pyramid

### Unit tests

- Policy validation.
- Domain allowlist matching.
- URL normalization.
- Audit hash chain.
- Evidence classification.
- Adapter output parsing.

### Integration tests

- CLI validate command against local mock server.
- Policy + audit + adapter flow.
- Approval queue transitions.

### Security tests

- Out-of-scope target is denied.
- Unsupported scheme is denied.
- Missing authorization is denied.
- Secrets are redacted.
- AI-proposed raw shell action is denied.

### UX tests later

- Scope setup flow.
- Approval flow.
- Report export.

## Quality gates

- `pytest` must pass.
- Type checks later.
- Linting later.
- No secrets committed.
- Docs updated when behavior changes.
