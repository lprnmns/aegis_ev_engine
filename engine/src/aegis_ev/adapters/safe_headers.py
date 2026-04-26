from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from uuid import uuid4

from aegis_ev.checks.web_headers import WebHeaderAnalysisInput, analyze_web_headers
from aegis_ev.models import Evidence, EvidenceKind, Finding
from datetime import datetime, timezone


@dataclass(frozen=True)
class HeaderCheckResult:
    evidence: Evidence
    findings: list[Finding]


def analyze_headers(target: str, status_code: int, headers: Mapping[str, str]) -> HeaderCheckResult:
    normalized = {k.lower(): v for k, v in headers.items()}
    results = analyze_web_headers(
        WebHeaderAnalysisInput(
            target=target,
            status_code=status_code,
            headers=normalized,
        )
    )
    evidence = Evidence(
        id=f"ev_{uuid4().hex}",
        kind=EvidenceKind.HTTP_HEADER_OBSERVATION,
        target=target,
        observed_at=datetime.now(timezone.utc),
        data={"status_code": status_code, "headers": dict(normalized)},
    )
    findings = [
        Finding(
            id=f"finding_{uuid4().hex}",
            title=result.title,
            severity=result.severity,
            confidence=result.confidence,
            evidence_ids=[evidence.id],
            remediation=result.remediation,
            status=result.status,
        )
        for result in results
    ]
    return HeaderCheckResult(evidence=evidence, findings=findings)
