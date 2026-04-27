from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from uuid import uuid4

from .audit import AuditLog, redact_target, redact_value
from .checks.web_headers import (
    WebHeaderAnalysisInput,
    analyze_web_headers,
    evidence_from_web_header_check,
    finding_from_web_header_check,
)
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence, FindingRecord
from .models import AuthorizationProfile, ImpactLevel, PolicyDecision, RequestBudget, ToolIntent
from .policy import PolicyEngine


DEFAULT_METHOD = "HEAD"
ALLOWED_METHODS = {"HEAD", "GET"}
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_TIMEOUT_SECONDS = 5
SAFE_REQUEST_HEADERS: dict[str, str] = {"User-Agent": "AegisEV-SafeMetadataFetch/0.1"}
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"}


@dataclass(frozen=True)
class SafeHttpFetchRequest:
    target: str
    authorization_profile: AuthorizationProfile
    fetch_id: str = field(default_factory=lambda: f"fetch_{uuid4().hex}")
    method: str = DEFAULT_METHOD
    requested_by: str = "contract"
    actor: str = "contract"
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    requested_impact_level: ImpactLevel | str = ImpactLevel.GREEN
    requests_used: int = 0
    now: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = str(self.method or DEFAULT_METHOD).upper()
        if method not in ALLOWED_METHODS:
            raise ValueError("method must be HEAD or GET")
        if self.max_redirects < 0 or self.max_redirects > 5:
            raise ValueError("max_redirects must be between 0 and 5")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 30:
            raise ValueError("timeout_seconds must be between 1 and 30")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "requested_by", redact_value(self.requested_by))
        object.__setattr__(self, "actor", redact_value(self.actor))
        object.__setattr__(self, "metadata", redact_value(self.metadata))


@dataclass(frozen=True)
class SafeHttpTransportResponse:
    status_code: int | None = None
    final_url: str | None = None
    headers: Mapping[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    error: str | None = None


@dataclass(frozen=True)
class SafeHttpFetchResult:
    fetch_id: str
    target: str
    normalized_target: str | None
    method: str
    requested_by: str
    actor: str
    policy_decision: dict[str, Any] | None
    allowed: bool
    status_code: int | None = None
    final_url: str | None = None
    redirect_chain: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    headers: dict[str, Any] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    elapsed_ms: int = 0
    error: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    no_body_stored: bool = True
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fetch_id": self.fetch_id,
            "target": self.target,
            "normalized_target": self.normalized_target,
            "method": self.method,
            "requested_by": self.requested_by,
            "actor": self.actor,
            "policy_decision": redact_value(self.policy_decision),
            "allowed": self.allowed,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "redirect_chain": redact_value(list(self.redirect_chain)),
            "headers": redact_value(self.headers),
            "content_type": self.content_type,
            "content_length": self.content_length,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "warnings": list(self.warnings),
            "redaction_applied": self.redaction_applied,
            "no_body_stored": self.no_body_stored,
            "created_at_utc": self.created_at_utc,
            "metadata": redact_value(self.metadata),
        }


Transport = Callable[[str, str, int], SafeHttpTransportResponse]


def safe_http_fetch(
    request: SafeHttpFetchRequest,
    *,
    transport: Transport | None = None,
    audit_log: AuditLog | None = None,
    policy_engine: PolicyEngine | None = None,
) -> SafeHttpFetchResult:
    policy_engine = policy_engine or PolicyEngine()
    transport = transport or urllib_metadata_transport
    warnings: list[str] = []
    created = (request.now or datetime.now(timezone.utc)).isoformat()
    decision = _policy_decision(request, request.target, policy_engine)
    _audit(audit_log, request, "http_fetch_requested", request.target, decision, None, False, created)
    if not decision.allowed:
        result = _result(
            request,
            decision,
            allowed=False,
            created_at_utc=created,
            error=decision.code,
            warnings=warnings,
        )
        _audit(audit_log, request, "http_fetch_denied", request.target, decision, result, False, created)
        return result

    current_url = decision.normalized_target or request.target
    redirects: list[dict[str, Any]] = []
    elapsed_total = 0
    for redirect_index in range(request.max_redirects + 1):
        try:
            response = transport(request.method, current_url, request.timeout_seconds)
        except Exception as exc:
            result = _result(
                request,
                decision,
                allowed=True,
                created_at_utc=created,
                final_url=current_url,
                redirect_chain=redirects,
                error=f"transport_error: {type(exc).__name__}",
                warnings=warnings,
            )
            _audit(audit_log, request, "http_fetch_failed", current_url, decision, result, True, created)
            return result
        elapsed_total += max(int(response.elapsed_ms or 0), 0)
        headers, redacted = _safe_headers(response.headers)
        status = response.status_code
        if response.error:
            result = _result(
                request,
                decision,
                allowed=True,
                created_at_utc=created,
                status_code=status,
                final_url=response.final_url or current_url,
                redirect_chain=redirects,
                headers=headers,
                elapsed_ms=elapsed_total,
                error=response.error,
                warnings=warnings,
                redaction_applied=redacted,
            )
            _audit(audit_log, request, "http_fetch_failed", current_url, decision, result, True, created)
            return result
        location = _header_lookup(headers, "location")
        final_url = redact_target(response.final_url or current_url)
        if status in {301, 302, 303, 307, 308} and location:
            if redirect_index >= request.max_redirects:
                warnings.append("redirect_limit_reached")
                result = _result(
                    request,
                    decision,
                    allowed=True,
                    created_at_utc=created,
                    status_code=status,
                    final_url=final_url,
                    redirect_chain=redirects,
                    headers=headers,
                    elapsed_ms=elapsed_total,
                    error="redirect_limit_reached",
                    warnings=warnings,
                    redaction_applied=redacted,
                )
                _audit(audit_log, request, "http_fetch_failed", current_url, decision, result, True, created)
                return result
            next_url = urllib.parse.urljoin(current_url, str(location))
            next_decision = _policy_decision(request, next_url, policy_engine)
            redirects.append({"status_code": status, "url": final_url, "location": redact_target(next_url)})
            if not next_decision.allowed:
                warnings.append("redirect_target_denied_by_policy")
                result = _result(
                    request,
                    next_decision,
                    allowed=False,
                    created_at_utc=created,
                    status_code=status,
                    final_url=final_url,
                    redirect_chain=redirects,
                    headers=headers,
                    elapsed_ms=elapsed_total,
                    error=next_decision.code,
                    warnings=warnings,
                    redaction_applied=redacted,
                )
                _audit(audit_log, request, "http_fetch_denied", next_url, next_decision, result, True, created)
                return result
            current_url = next_decision.normalized_target or next_url
            decision = next_decision
            continue
        result = _result(
            request,
            decision,
            allowed=True,
            created_at_utc=created,
            status_code=status,
            final_url=final_url,
            redirect_chain=redirects,
            headers=headers,
            content_type=_header_lookup(headers, "content-type"),
            content_length=_content_length(headers),
            elapsed_ms=elapsed_total,
            warnings=warnings,
            redaction_applied=redacted,
            metadata={"tls_https_indicator": (urllib.parse.urlsplit(final_url or "").scheme == "https")},
        )
        _audit(audit_log, request, "http_fetch_completed", current_url, decision, result, True, created)
        return result

    return _result(request, decision, allowed=False, created_at_utc=created, error="unexpected_fetch_state", warnings=warnings)


def urllib_metadata_transport(method: str, url: str, timeout_seconds: int) -> SafeHttpTransportResponse:
    request = urllib.request.Request(url, method=method, headers=SAFE_REQUEST_HEADERS)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            elapsed = int((time.monotonic() - started) * 1000)
            return SafeHttpTransportResponse(
                status_code=response.getcode(),
                final_url=response.geturl(),
                headers=dict(response.headers.items()),
                elapsed_ms=elapsed,
            )
    except urllib.error.HTTPError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        if 300 <= exc.code < 400:
            return SafeHttpTransportResponse(
                status_code=exc.code,
                final_url=exc.geturl(),
                headers=dict(exc.headers.items()),
                elapsed_ms=elapsed,
            )
        return SafeHttpTransportResponse(
            status_code=exc.code,
            final_url=exc.geturl(),
            headers=dict(exc.headers.items()),
            elapsed_ms=elapsed,
            error=f"http_error_{exc.code}",
        )
    except urllib.error.URLError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return SafeHttpTransportResponse(final_url=url, elapsed_ms=elapsed, error=f"url_error: {redact_value(str(exc.reason))}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def evidence_from_fetch_result(result: SafeHttpFetchResult) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.SAFE_HTTP_FETCH,
        source_id=result.fetch_id,
        target=result.target,
        normalized_target=result.normalized_target,
        title="Safe HTTP metadata fetch",
        summary=f"Fetched HTTP metadata with status {result.status_code}; captured {len(result.headers)} header(s).",
        structured_data=result.to_dict(),
        tags=("http-fetch", "metadata", "no-body"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def analyze_headers_from_fetch_result(result: SafeHttpFetchResult) -> tuple[list[dict[str, Any]], list[EvidenceRecord], list[FindingRecord]]:
    if not result.allowed or result.error:
        return [], [], []
    checks = analyze_web_headers(
        WebHeaderAnalysisInput(
            target=result.target,
            normalized_target=result.normalized_target,
            status_code=result.status_code,
            headers=result.headers,
            content_type=result.content_type,
            protocol=urllib.parse.urlsplit(result.final_url or result.normalized_target or result.target).scheme,
            observed_redirects=tuple(item.get("location", "") for item in result.redirect_chain),
            source_reference=result.fetch_id,
        )
    )
    evidence = [evidence_from_web_header_check(item, related_adapter_id="safe_http_fetch") for item in checks]
    findings = [finding_from_web_header_check(item, record) for item, record in zip(checks, evidence, strict=True)]
    return [item.to_dict() for item in checks], evidence, findings


def fixture_transport(payload: dict[str, Any]) -> Transport:
    responses = payload.get("responses")
    if responses is None:
        responses = [payload]
    if not isinstance(responses, list) or not responses:
        raise ValueError("transport_fixture.responses must be a non-empty list")
    queue = list(responses)

    def _transport(method: str, url: str, timeout_seconds: int) -> SafeHttpTransportResponse:
        if not queue:
            item = responses[-1]
        else:
            item = queue.pop(0)
        if not isinstance(item, dict):
            raise ValueError("transport fixture response must be an object")
        if item.get("raise_timeout"):
            raise TimeoutError("fixture timeout")
        return SafeHttpTransportResponse(
            status_code=item.get("status_code"),
            final_url=item.get("final_url", url),
            headers=item.get("headers", {}),
            elapsed_ms=int(item.get("elapsed_ms", 0)),
            error=item.get("error"),
        )

    return _transport


def _policy_decision(request: SafeHttpFetchRequest, target: str, policy_engine: PolicyEngine) -> PolicyDecision:
    return policy_engine.evaluate(
        ToolIntent(
            adapter="safe_http_fetch",
            target=target,
            impact=request.requested_impact_level,
            budget=RequestBudget(max_requests=1, timeout_seconds=request.timeout_seconds, max_response_bytes=1),
            action_type="fetch_http_metadata",
            requires_authentication=False,
            requests_used=request.requests_used,
        ),
        request.authorization_profile,
        now=request.now,
    )


def _result(
    request: SafeHttpFetchRequest,
    decision: PolicyDecision,
    *,
    allowed: bool,
    created_at_utc: str,
    status_code: int | None = None,
    final_url: str | None = None,
    redirect_chain: list[dict[str, Any]] | None = None,
    headers: dict[str, Any] | None = None,
    content_type: str | None = None,
    content_length: int | None = None,
    elapsed_ms: int = 0,
    error: str | None = None,
    warnings: list[str] | None = None,
    redaction_applied: bool = False,
    metadata: dict[str, Any] | None = None,
) -> SafeHttpFetchResult:
    return SafeHttpFetchResult(
        fetch_id=request.fetch_id,
        target=redact_target(request.target) or "<invalid-target>",
        normalized_target=decision.normalized_target,
        method=request.method,
        requested_by=str(request.requested_by),
        actor=str(request.actor),
        policy_decision=decision.to_public_dict(),
        allowed=allowed,
        status_code=status_code,
        final_url=redact_target(final_url),
        redirect_chain=tuple(redact_value(redirect_chain or [])),
        headers=headers or {},
        content_type=content_type,
        content_length=content_length,
        elapsed_ms=elapsed_ms,
        error=error,
        warnings=tuple(warnings or []),
        redaction_applied=bool(redaction_applied),
        no_body_stored=True,
        created_at_utc=created_at_utc,
        metadata=redact_value(metadata or {}),
    )


def _safe_headers(headers: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    safe: dict[str, Any] = {}
    redacted = False
    for key, value in headers.items():
        name = str(key)
        lowered = name.lower()
        if lowered in SENSITIVE_HEADERS or any(part in lowered for part in ("token", "secret", "session")):
            safe[name] = "<redacted>"
            redacted = True
        else:
            scrubbed = redact_value(value)
            if scrubbed != value:
                redacted = True
            safe[name] = scrubbed
    return safe, redacted


def _header_lookup(headers: Mapping[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return str(value)
    return None


def _content_length(headers: Mapping[str, Any]) -> int | None:
    value = _header_lookup(headers, "content-length")
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _audit(
    audit_log: AuditLog | None,
    request: SafeHttpFetchRequest,
    event_type: str,
    target: str | None,
    decision: PolicyDecision,
    result: SafeHttpFetchResult | None,
    redaction_applied: bool,
    timestamp: str,
) -> None:
    if audit_log is None:
        return
    audit_log.append(
        actor=request.actor,
        action=event_type,
        target=target,
        details={
            "fetch_id": request.fetch_id,
            "method": request.method,
            "status_code": result.status_code if result else None,
            "decision_code": decision.code,
            "allowed": result.allowed if result else decision.allowed,
            "redaction_applied": redaction_applied or (result.redaction_applied if result else False),
            "no_body_stored": True,
        },
        event_type=event_type,
        normalized_target=decision.normalized_target,
        impact_level=str(request.requested_impact_level.value if isinstance(request.requested_impact_level, ImpactLevel) else request.requested_impact_level),
        decision_code=decision.code,
        allowed=result.allowed if result else decision.allowed,
        required_approval=decision.required_approval,
        timestamp_utc=timestamp,
    )
