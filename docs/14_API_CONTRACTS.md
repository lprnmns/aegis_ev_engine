# API Contracts

## Engine command surface

The Tauri app should call the Python engine through a narrow command surface. No raw arbitrary command execution.

### Validate target

```json
{
  "command": "validate_target",
  "target": "https://app.example.com",
  "authorization_profile_id": "auth_123",
  "mode": "safe"
}
```

### Submit approval

```json
{
  "command": "submit_approval",
  "approval_id": "approval_123",
  "decision": "approved",
  "comment": "Customer approved this check in ticket SEC-123."
}
```

### Get audit events

```json
{
  "command": "get_audit_events",
  "job_id": "job_123"
}
```

## Adapter interface

All adapters should expose:

```python
class ToolAdapter(Protocol):
    name: str
    impact: ImpactLevel
    def plan(self, target: str) -> ToolIntent: ...
    def run(self, intent: ToolIntent, policy: PolicyDecision) -> AdapterResult: ...
```

## AI interface

AI providers should return structured JSON, validated by schema. Free-form text is allowed only for human-readable explanation fields.
