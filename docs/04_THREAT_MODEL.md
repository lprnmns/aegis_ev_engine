# Threat Model

## Assets

- Customer target definitions.
- Authorization profiles.
- API keys and model provider credentials.
- HTTP request/response evidence.
- Reports.
- Audit logs.
- Tool outputs.
- Local workspace files.

## Threat actors

- Unauthorized user running the tool against third-party targets.
- Malicious prompt or imported document trying to override guardrails.
- Compromised CLI tool or template package.
- Accidental user misconfiguration.
- Insider leaking reports or tokens.
- Bug causing excessive traffic.

## Key threats and mitigations

| Threat | Mitigation |
|---|---|
| Out-of-scope target interaction | Domain/CIDR allowlist; fail closed |
| LLM prompt injection | LLM cannot execute; policy is deterministic |
| Token leakage | Env vars, OS keychain later, redaction, no secrets in repo |
| Excessive traffic | Token bucket, concurrency limits, runtime caps |
| Stealth misuse | No auto IP switching; approved egress only |
| Tampered logs | Hash-chained audit log |
| Dangerous tools | Adapter-level impact classification and approvals |
| False positives | Evidence model, verifier, confidence scoring, retest |
| Supply-chain compromise | Pin versions, SBOM later, signed adapter registry later |

## Abuse resistance requirements

- The app should refuse target interaction if no authorization profile exists.
- The app should stop, not evade, when blocked.
- The app should record every denied action.
- The app should require explicit user action for high-impact tests.
