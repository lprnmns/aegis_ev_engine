# Risk Register

| Risk | Severity | Probability | Mitigation |
|---|---:|---:|---|
| Product perceived as offensive hacking tool | High | Medium | Defensive language, safe defaults, no stealth features |
| Scope creep across Web/Mobile/Desktop | High | High | Web/API-only v0.1; ADR enforced |
| LLM hallucinated finding | High | High | Evidence-backed state machine; AI text not evidence |
| Excessive traffic to target | High | Medium | Budget enforcement, throttling, stop-on-block |
| Secret leakage | Critical | Medium | Redaction, no secrets in repo, GitHub push protection |
| Tool supply-chain compromise | High | Medium | Pin versions, adapter registry, SBOM later |
| Fragile AI provider integration | Medium | Medium | Official APIs only; provider abstraction |
| Poor UX from too many approvals | Medium | Medium | Clear impact labels, sensible Safe Mode defaults |
| Enterprise distrust of BYOK handling | High | Medium | Local key storage, clear data flow docs, audit logs |
