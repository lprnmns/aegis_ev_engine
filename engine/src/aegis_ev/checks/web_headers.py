from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from aegis_ev.audit import redact_target, redact_value
from aegis_ev.evidence import (
    EvidenceRecord,
    EvidenceSourceType,
    EvidenceType,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
    RetestStatus,
    VerificationState,
)


SENSITIVE_COOKIE_PARTS = ("auth", "csrf", "id", "jwt", "sess", "sid", "state", "token")
SENSITIVE_PATH_PARTS = ("account", "auth", "login", "logout", "oauth", "session", "signin", "signup")
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
DISCLOSURE_HEADERS = ("server", "x-aspnet-version", "x-generator", "x-powered-by", "x-runtime")


@dataclass(frozen=True)
class WebHeaderAnalysisInput:
    target: str
    normalized_target: str | None = None
    status_code: int | None = None
    headers: Mapping[str, Any] = field(default_factory=dict)
    content_type: str | None = None
    protocol: str | None = None
    tls_summary: Mapping[str, Any] | None = None
    observed_redirects: tuple[str, ...] = field(default_factory=tuple)
    source_reference: str | None = None
    request_origin: str | None = None
    security_txt_present: bool | None = None


@dataclass(frozen=True)
class WebHeaderCheckResult:
    check_id: str
    title: str
    severity: str
    confidence: str
    status: str
    target: str
    normalized_target: str | None
    category: str
    cwe_id: str | None
    owasp_reference: str | None
    evidence_summary: str
    remediation: str
    tags: tuple[str, ...]
    raw_observation: dict[str, Any]
    finding_candidate: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "target": self.target,
            "normalized_target": self.normalized_target,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "owasp_reference": self.owasp_reference,
            "evidence_summary": self.evidence_summary,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "raw_observation": redact_value(self.raw_observation),
            "finding_candidate": self.finding_candidate,
        }


def analyze_web_headers(payload: WebHeaderAnalysisInput) -> list[WebHeaderCheckResult]:
    normalized_target = payload.normalized_target or _normalize_target(payload.target)
    headers = _normalize_headers(payload.headers)
    results: list[WebHeaderCheckResult] = []
    csp_value = _first_header(headers, "content-security-policy")
    frame_ancestors_present = _csp_has_frame_ancestors(csp_value)
    scheme = _scheme_from_target(normalized_target or payload.target)
    content_type = (payload.content_type or _first_header(headers, "content-type") or "").lower()

    if csp_value is None:
        results.append(
            _result(
                check_id="missing_csp",
                title="Missing Content-Security-Policy header",
                severity=FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="secure_configuration",
                cwe_id="CWE-693",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="No Content-Security-Policy header was present in the supplied response metadata.",
                remediation="Add a restrictive Content-Security-Policy header with explicit source directives.",
                tags=("configuration", "csp", "headers", "web"),
                raw_observation={"headers": _select_headers(headers, ("content-security-policy",))},
            )
        )
    else:
        weak_reasons = _weak_csp_reasons(csp_value)
        if weak_reasons:
            results.append(
                _result(
                    check_id="weak_csp",
                    title="Potentially weak Content-Security-Policy configuration",
                    severity=FindingSeverity.MEDIUM.value if "wildcard source" in weak_reasons or "unsafe-inline" in weak_reasons else FindingSeverity.LOW.value,
                    confidence=FindingConfidence.MEDIUM.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="secure_configuration",
                    cwe_id="CWE-693",
                    owasp_reference="A05:2021 Security Misconfiguration",
                    evidence_summary=f"Observed CSP may be weaker than intended: {', '.join(weak_reasons)}.",
                    remediation="Tighten the CSP by removing wildcard or unsafe directives and defining a restrictive default-src policy.",
                    tags=("configuration", "csp", "headers", "web"),
                    raw_observation={"headers": _select_headers(headers, ("content-security-policy",))},
                )
            )

    if _first_header(headers, "x-frame-options") is None and not frame_ancestors_present:
        results.append(
            _result(
                check_id="missing_clickjacking_protection",
                title="Missing clickjacking protection headers",
                severity=FindingSeverity.MEDIUM.value if not content_type or "html" in content_type else FindingSeverity.LOW.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="secure_configuration",
                cwe_id="CWE-1021",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="Neither X-Frame-Options nor a CSP frame-ancestors directive was present in the supplied response metadata.",
                remediation="Set X-Frame-Options or add a restrictive frame-ancestors directive to the CSP.",
                tags=("clickjacking", "headers", "web"),
                raw_observation={"headers": _select_headers(headers, ("x-frame-options", "content-security-policy"))},
            )
        )

    hsts = _first_header(headers, "strict-transport-security")
    if scheme == "https":
        if hsts is None:
            results.append(
                _result(
                    check_id="missing_hsts",
                    title="Missing Strict-Transport-Security header on HTTPS target",
                    severity=FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.HIGH.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="transport_security",
                    cwe_id="CWE-319",
                    owasp_reference="A02:2021 Cryptographic Failures",
                    evidence_summary="The supplied HTTPS response metadata did not include a Strict-Transport-Security header.",
                    remediation="Add Strict-Transport-Security with a suitable max-age after validating rollout safety.",
                    tags=("headers", "hsts", "tls", "web"),
                    raw_observation={"headers": _select_headers(headers, ("strict-transport-security",))},
                )
            )
        elif _weak_hsts(hsts):
            results.append(
                _result(
                    check_id="weak_hsts",
                    title="Potentially weak Strict-Transport-Security configuration",
                    severity=FindingSeverity.LOW.value,
                    confidence=FindingConfidence.MEDIUM.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="transport_security",
                    cwe_id="CWE-319",
                    owasp_reference="A02:2021 Cryptographic Failures",
                    evidence_summary="The supplied Strict-Transport-Security header uses a short max-age value.",
                    remediation="Increase HSTS max-age to a durable value after confirming domain readiness.",
                    tags=("headers", "hsts", "tls", "web"),
                    raw_observation={"headers": _select_headers(headers, ("strict-transport-security",))},
                )
            )

    if (_first_header(headers, "x-content-type-options") or "").lower() != "nosniff":
        results.append(
            _result(
                check_id="missing_nosniff",
                title="Missing X-Content-Type-Options: nosniff",
                severity=FindingSeverity.LOW.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="secure_configuration",
                cwe_id="CWE-16",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="The supplied response metadata did not include X-Content-Type-Options: nosniff.",
                remediation="Set X-Content-Type-Options to nosniff.",
                tags=("headers", "mime", "web"),
                raw_observation={"headers": _select_headers(headers, ("x-content-type-options",))},
            )
        )

    referrer_policy = _first_header(headers, "referrer-policy")
    if referrer_policy is None:
        results.append(
            _result(
                check_id="missing_referrer_policy",
                title="Missing Referrer-Policy header",
                severity=FindingSeverity.LOW.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="privacy_configuration",
                cwe_id="CWE-200",
                owasp_reference="A01:2021 Broken Access Control",
                evidence_summary="No Referrer-Policy header was present in the supplied response metadata.",
                remediation="Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
                tags=("headers", "privacy", "web"),
                raw_observation={"headers": _select_headers(headers, ("referrer-policy",))},
            )
        )
    elif referrer_policy.lower() not in SAFE_REFERRER_POLICIES:
        results.append(
            _result(
                check_id="unsafe_referrer_policy",
                title="Potentially unsafe Referrer-Policy configuration",
                severity=FindingSeverity.LOW.value,
                confidence=FindingConfidence.MEDIUM.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="privacy_configuration",
                cwe_id="CWE-200",
                owasp_reference="A01:2021 Broken Access Control",
                evidence_summary=f"Observed Referrer-Policy value '{referrer_policy}' may disclose more context than intended.",
                remediation="Use a stricter Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
                tags=("headers", "privacy", "web"),
                raw_observation={"headers": _select_headers(headers, ("referrer-policy",))},
            )
        )

    permissions_policy = _first_header(headers, "permissions-policy")
    if permissions_policy is None:
        results.append(
            _result(
                check_id="missing_permissions_policy",
                title="Missing Permissions-Policy header",
                severity=FindingSeverity.INFO.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="secure_configuration",
                cwe_id="CWE-16",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="No Permissions-Policy header was present in the supplied response metadata.",
                remediation="Define a least-privilege Permissions-Policy for unneeded browser features.",
                tags=("headers", "permissions-policy", "web"),
                raw_observation={"headers": _select_headers(headers, ("permissions-policy",))},
            )
        )
    elif "*" in permissions_policy:
        results.append(
            _result(
                check_id="permissive_permissions_policy",
                title="Potentially overly permissive Permissions-Policy",
                severity=FindingSeverity.LOW.value,
                confidence=FindingConfidence.MEDIUM.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="secure_configuration",
                cwe_id="CWE-16",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="Observed Permissions-Policy contains wildcard allowances.",
                remediation="Restrict Permissions-Policy to explicitly required features and origins.",
                tags=("headers", "permissions-policy", "web"),
                raw_observation={"headers": _select_headers(headers, ("permissions-policy",))},
            )
        )

    cors_results = _cors_results(payload, headers, normalized_target)
    results.extend(cors_results)
    results.extend(_cookie_results(payload, headers, normalized_target))
    results.extend(_disclosure_results(payload, headers, normalized_target))

    if _is_sensitive_path(normalized_target or payload.target):
        cache_control = (_first_header(headers, "cache-control") or "").lower()
        pragma = (_first_header(headers, "pragma") or "").lower()
        if "no-store" not in cache_control and "private" not in cache_control and "no-cache" not in pragma:
            results.append(
                _result(
                    check_id="sensitive_path_cache_control",
                    title="Sensitive-looking path missing protective cache directives",
                    severity=FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.MEDIUM.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="secure_configuration",
                    cwe_id="CWE-525",
                    owasp_reference="A05:2021 Security Misconfiguration",
                    evidence_summary="The supplied metadata for a sensitive-looking path did not include cache-control protections such as no-store or private.",
                    remediation="Use Cache-Control: no-store or private for authentication and session-related paths where appropriate.",
                    tags=("cache-control", "headers", "web"),
                    raw_observation={"headers": _select_headers(headers, ("cache-control", "pragma"))},
                )
            )

    if payload.security_txt_present is False:
        results.append(
            _result(
                check_id="security_txt_not_observed",
                title="security.txt not observed in supplied metadata",
                severity=FindingSeverity.INFO.value,
                confidence=FindingConfidence.LOW.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="governance",
                cwe_id=None,
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="The provided metadata explicitly indicated that security.txt was not observed. This is informational only because no live fetch occurred.",
                remediation="Publish a security.txt file if operationally appropriate.",
                tags=("governance", "security-txt", "web"),
                raw_observation={"security_txt_present": False},
            )
        )

    return results


def evidence_from_web_header_check(
    result: WebHeaderCheckResult,
    *,
    related_audit_event_id: str | None = None,
    related_adapter_id: str | None = "web_header_config_check",
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.WEB_HEADER_CHECK,
        source_id=result.check_id,
        target=result.target,
        normalized_target=result.normalized_target,
        title=result.title,
        summary=result.evidence_summary,
        redacted_raw=result.raw_observation,
        structured_data=result.to_dict(),
        related_audit_event_id=related_audit_event_id,
        related_adapter_id=related_adapter_id,
        tags=result.tags,
        confidence=result.confidence,
        redaction_applied=True,
    )


def finding_from_web_header_check(result: WebHeaderCheckResult, evidence: EvidenceRecord) -> FindingRecord:
    confidence = FindingConfidence(result.confidence)
    status = FindingStatus.CANDIDATE if confidence in {FindingConfidence.MEDIUM, FindingConfidence.HIGH} else FindingStatus.DRAFT
    return FindingRecord(
        title=result.title,
        description=result.evidence_summary,
        severity=result.severity,
        confidence=result.confidence,
        status=status,
        target=result.target,
        normalized_target=result.normalized_target,
        category=result.category,
        cwe_id=result.cwe_id,
        owasp_reference=result.owasp_reference,
        evidence_ids=(evidence.evidence_id,),
        remediation=result.remediation,
        retest_status=RetestStatus.NOT_RETESTED,
        verification_state=VerificationState.EVIDENCE_BACKED,
        tags=result.tags,
    )


def _cors_results(
    payload: WebHeaderAnalysisInput,
    headers: dict[str, list[str]],
    normalized_target: str | None,
) -> list[WebHeaderCheckResult]:
    results: list[WebHeaderCheckResult] = []
    allow_origin = _first_header(headers, "access-control-allow-origin")
    allow_credentials = (_first_header(headers, "access-control-allow-credentials") or "").lower() == "true"
    if allow_origin == "*":
        results.append(
            _result(
                check_id="cors_wildcard_credentials" if allow_credentials else "cors_wildcard_origin",
                title="Potentially unsafe CORS configuration allows wildcard origin with credentials"
                if allow_credentials
                else "Potentially unsafe CORS configuration allows wildcard origin",
                severity=FindingSeverity.HIGH.value if allow_credentials else FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.HIGH.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="access_control",
                cwe_id="CWE-942",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="The supplied response metadata included Access-Control-Allow-Origin: *"
                + (" together with Access-Control-Allow-Credentials: true." if allow_credentials else "."),
                remediation="Restrict CORS origins to trusted allowlisted origins and avoid wildcard origins for sensitive resources.",
                tags=("cors", "headers", "web"),
                raw_observation={"headers": _select_headers(headers, ("access-control-allow-origin", "access-control-allow-credentials"))},
            )
        )
    elif payload.request_origin and allow_origin and allow_origin == payload.request_origin and allow_credentials:
        results.append(
            _result(
                check_id="cors_reflected_origin_credentials",
                title="Potentially unsafe CORS configuration reflects a supplied origin with credentials",
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.MEDIUM.value,
                target=payload.target,
                normalized_target=normalized_target,
                category="access_control",
                cwe_id="CWE-942",
                owasp_reference="A05:2021 Security Misconfiguration",
                evidence_summary="The supplied metadata showed an Access-Control-Allow-Origin value matching the provided request origin while credentials were enabled.",
                remediation="Avoid reflecting origins dynamically for credentialed CORS responses unless strict allowlist checks are enforced.",
                tags=("cors", "headers", "web"),
                raw_observation={
                    "headers": _select_headers(headers, ("access-control-allow-origin", "access-control-allow-credentials")),
                    "request_origin": redact_value(payload.request_origin),
                },
            )
        )
    return results


def _cookie_results(
    payload: WebHeaderAnalysisInput,
    headers: dict[str, list[str]],
    normalized_target: str | None,
) -> list[WebHeaderCheckResult]:
    results: list[WebHeaderCheckResult] = []
    scheme = _scheme_from_target(normalized_target or payload.target)
    for cookie in _parse_set_cookie_headers(headers):
        secure = "secure" in cookie["flags"]
        httponly = "httponly" in cookie["flags"]
        samesite = any(flag.startswith("samesite=") for flag in cookie["flags"])
        sensitive = _is_sensitive_cookie_name(cookie["name"])
        base_observation = {
            "cookie_name": cookie["name"],
            "set_cookie": cookie["redacted"],
        }
        if scheme == "https" and not secure:
            results.append(
                _result(
                    check_id=f"cookie_missing_secure_{cookie['name'].lower()}",
                    title=f"Cookie '{cookie['name']}' missing Secure attribute",
                    severity=FindingSeverity.HIGH.value if sensitive else FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.HIGH.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="session_security",
                    cwe_id="CWE-614",
                    owasp_reference="A07:2021 Identification and Authentication Failures",
                    evidence_summary=f"The supplied Set-Cookie metadata for '{cookie['name']}' did not include the Secure attribute.",
                    remediation="Set the Secure attribute for cookies issued over HTTPS.",
                    tags=("cookies", "headers", "session", "web"),
                    raw_observation=base_observation,
                )
            )
        if sensitive and not httponly:
            severity = FindingSeverity.HIGH.value
        else:
            severity = FindingSeverity.MEDIUM.value
        if not httponly:
            results.append(
                _result(
                    check_id=f"cookie_missing_httponly_{cookie['name'].lower()}",
                    title=f"Cookie '{cookie['name']}' missing HttpOnly attribute",
                    severity=severity,
                    confidence=FindingConfidence.HIGH.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="session_security",
                    cwe_id="CWE-1004",
                    owasp_reference="A03:2021 Injection",
                    evidence_summary=f"The supplied Set-Cookie metadata for '{cookie['name']}' did not include the HttpOnly attribute.",
                    remediation="Set the HttpOnly attribute on cookies that do not require client-side script access.",
                    tags=("cookies", "headers", "session", "web"),
                    raw_observation=base_observation,
                )
            )
        if not samesite:
            results.append(
                _result(
                    check_id=f"cookie_missing_samesite_{cookie['name'].lower()}",
                    title=f"Cookie '{cookie['name']}' missing SameSite attribute",
                    severity=FindingSeverity.MEDIUM.value if sensitive else FindingSeverity.LOW.value,
                    confidence=FindingConfidence.HIGH.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="session_security",
                    cwe_id="CWE-352",
                    owasp_reference="A01:2021 Broken Access Control",
                    evidence_summary=f"The supplied Set-Cookie metadata for '{cookie['name']}' did not include a SameSite attribute.",
                    remediation="Add an appropriate SameSite attribute, such as Lax or Strict, to reduce CSRF exposure.",
                    tags=("cookies", "headers", "session", "web"),
                    raw_observation=base_observation,
                )
            )
    return results


def _disclosure_results(
    payload: WebHeaderAnalysisInput,
    headers: dict[str, list[str]],
    normalized_target: str | None,
) -> list[WebHeaderCheckResult]:
    results: list[WebHeaderCheckResult] = []
    for header in DISCLOSURE_HEADERS:
        value = _first_header(headers, header)
        if value:
            results.append(
                _result(
                    check_id=f"tech_disclosure_{header.replace('-', '_')}",
                    title=f"Technology disclosure via {header} header",
                    severity=FindingSeverity.LOW.value if header == "server" else FindingSeverity.INFO.value,
                    confidence=FindingConfidence.HIGH.value,
                    target=payload.target,
                    normalized_target=normalized_target,
                    category="information_exposure",
                    cwe_id="CWE-200",
                    owasp_reference="A05:2021 Security Misconfiguration",
                    evidence_summary=f"The supplied response metadata exposed technology details in the {header} header.",
                    remediation="Reduce unnecessary version or platform disclosure in response headers where operationally feasible.",
                    tags=("disclosure", "headers", "web"),
                    raw_observation={"headers": _select_headers(headers, (header,))},
                )
            )
    return results


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in headers.items():
        name = str(key).lower().strip()
        if not name:
            continue
        if isinstance(value, list):
            items = [str(item) for item in value]
        elif isinstance(value, tuple):
            items = [str(item) for item in value]
        else:
            items = [str(value)]
        normalized[name] = items
    return normalized


def _first_header(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name, [])
    return values[0] if values else None


def _select_headers(headers: dict[str, list[str]], names: tuple[str, ...]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for name in names:
        if name in headers:
            values = headers[name]
            selected[name] = values[0] if len(values) == 1 else values
    return redact_value(selected)


def _normalize_target(target: str) -> str:
    parsed = urlsplit(target)
    host = parsed.hostname or ""
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    return f"{parsed.scheme.lower()}://{netloc}{parsed.path}" if parsed.scheme else target


def _scheme_from_target(target: str) -> str:
    return urlsplit(target).scheme.lower()


def _csp_has_frame_ancestors(csp_value: str | None) -> bool:
    if not csp_value:
        return False
    return any(part.strip().lower().startswith("frame-ancestors") for part in csp_value.split(";"))


def _weak_csp_reasons(csp_value: str) -> list[str]:
    lowered = csp_value.lower()
    reasons: list[str] = []
    if "default-src" not in lowered:
        reasons.append("missing default-src")
    if "'unsafe-inline'" in lowered:
        reasons.append("unsafe-inline")
    if "'unsafe-eval'" in lowered:
        reasons.append("unsafe-eval")
    if " *" in lowered or lowered.startswith("*") or "://*" in lowered:
        reasons.append("wildcard source")
    return reasons


def _weak_hsts(value: str) -> bool:
    lowered = value.lower()
    for part in lowered.split(";"):
        item = part.strip()
        if item.startswith("max-age="):
            try:
                return int(item.split("=", 1)[1]) < 15_552_000
            except ValueError:
                return True
    return True


def _parse_set_cookie_headers(headers: dict[str, list[str]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for raw in headers.get("set-cookie", []):
        parts = [item.strip() for item in raw.split(";") if item.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name, _value = parts[0].split("=", 1)
        flags = tuple(part.lower() for part in parts[1:])
        parsed.append(
            {
                "name": name,
                "flags": flags,
                "redacted": redact_value(raw),
            }
        )
    return parsed


def _is_sensitive_cookie_name(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in SENSITIVE_COOKIE_PARTS)


def _is_sensitive_path(target: str) -> bool:
    path = urlsplit(target).path.lower()
    return any(part in path for part in SENSITIVE_PATH_PARTS)


def _result(
    *,
    check_id: str,
    title: str,
    severity: str,
    confidence: str,
    target: str,
    normalized_target: str | None,
    category: str,
    cwe_id: str | None,
    owasp_reference: str | None,
    evidence_summary: str,
    remediation: str,
    tags: tuple[str, ...],
    raw_observation: dict[str, Any],
) -> WebHeaderCheckResult:
    return WebHeaderCheckResult(
        check_id=check_id,
        title=title,
        severity=severity,
        confidence=confidence,
        status=FindingStatus.CANDIDATE.value if confidence != FindingConfidence.LOW.value else FindingStatus.DRAFT.value,
        target=redact_target(target) or "<invalid-target>",
        normalized_target=redact_target(normalized_target),
        category=category,
        cwe_id=cwe_id,
        owasp_reference=owasp_reference,
        evidence_summary=evidence_summary,
        remediation=remediation,
        tags=tuple(sorted(set(tags))),
        raw_observation=redact_value(raw_observation),
        finding_candidate=True,
    )
