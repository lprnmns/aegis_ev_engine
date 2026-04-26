# Data Model

## AuthorizationProfile

```json
{
  "id": "auth_123",
  "owner": "Acme Security Team",
  "allowed_domains": ["app.example.com"],
  "allowed_cidrs": [],
  "expires_at": "2026-12-31T23:59:59Z",
  "max_requests_per_minute": 30,
  "max_concurrency": 2,
  "approved_egress_profiles": ["corp-vpn-istanbul"],
  "notes": "Signed customer authorization stored externally."
}
```

## Job

```json
{
  "id": "job_123",
  "target": "https://app.example.com",
  "mode": "safe",
  "status": "running",
  "started_at": "2026-04-26T12:00:00Z"
}
```

## ToolIntent

```json
{
  "adapter": "safe_headers",
  "target": "https://app.example.com",
  "impact": "green",
  "budget": {
    "max_requests": 3,
    "timeout_seconds": 10
  }
}
```

## Evidence

```json
{
  "id": "ev_123",
  "kind": "http_header_observation",
  "target": "https://app.example.com",
  "observed_at": "2026-04-26T12:00:05Z",
  "data": {
    "status_code": 200,
    "headers": {
      "content-security-policy": "..."
    }
  }
}
```

## Finding

```json
{
  "id": "finding_123",
  "title": "Missing Content-Security-Policy header",
  "severity": "medium",
  "confidence": "high",
  "standard_refs": ["OWASP-ASVS-V14"],
  "evidence_ids": ["ev_123"],
  "retest_status": "not_started"
}
```

## AuditEvent

```json
{
  "id": "audit_123",
  "timestamp": "2026-04-26T12:00:01Z",
  "actor": "system",
  "action": "policy.allow",
  "target": "https://app.example.com",
  "previous_hash": "...",
  "hash": "..."
}
```
