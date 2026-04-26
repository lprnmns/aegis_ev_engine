from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from urllib.request import Request, urlopen
from uuid import uuid4

from aegis_ev.models import Evidence, EvidenceKind, Finding

SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Add a restrictive Content-Security-Policy header."),
    "x-frame-options": ("low", "Set X-Frame-Options or frame-ancestors in CSP to reduce clickjacking risk."),
    "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Set a privacy-preserving Referrer-Policy."),
    "permissions-policy": ("low", "Set a least-privilege Permissions-Policy."),
    "strict-transport-security": ("medium", "Set HSTS for HTTPS sites after validating rollout safety."),
}


@dataclass(frozen=True)
class HeaderCheckResult:
    evidence: Evidence
    findings: list[Finding]


def analyze_headers(target: str, status_code: int, headers: Mapping[str, str]) -> HeaderCheckResult:
    normalized = {k.lower(): v for k, v in headers.items()}
    evidence = Evidence(
        id=f"ev_{uuid4().hex}",
        kind=EvidenceKind.HTTP_HEADER_OBSERVATION,
        target=target,
        observed_at=datetime.now(timezone.utc),
        data={"status_code": status_code, "headers": dict(normalized)},
    )
    findings: list[Finding] = []
    for header, (severity, remediation) in SECURITY_HEADERS.items():
        if header not in normalized:
            findings.append(
                Finding(
                    id=f"finding_{uuid4().hex}",
                    title=f"Missing HTTP security header: {header}",
                    severity=severity,
                    confidence="medium",
                    evidence_ids=[evidence.id],
                    remediation=remediation,
                )
            )
    return HeaderCheckResult(evidence=evidence, findings=findings)


def fetch_and_analyze_headers(target: str, timeout_seconds: int = 10) -> HeaderCheckResult:
    """Perform one low-impact HTTP GET request and analyze response headers.

    This function assumes policy has already allowed the action.
    """
    request = Request(target, headers={"User-Agent": "AegisEV-SafeMode/0.1"}, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:  # nosec: target is policy-gated by caller
        status_code = int(response.status)
        headers = dict(response.headers.items())
    return analyze_headers(target, status_code, headers)
