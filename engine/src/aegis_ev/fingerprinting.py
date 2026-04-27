from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from .audit import canonical_json, redact_target, redact_value
from .evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


MAX_HTML_SNIPPET_BYTES = 32768
CONFIDENCE_VALUES = {"low", "medium", "high"}
TECH_CATEGORIES = {
    "analytics",
    "backend_framework",
    "build_tool",
    "cdn",
    "cms",
    "frontend_framework",
    "hosting",
    "language",
    "security_control",
    "unknown",
    "web_server",
}
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"}
SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
SURFACE_PARTS = ("admin", "dashboard", "login", "auth", "api", "graphql", "account", "billing", "upload")


@dataclass(frozen=True)
class DetectedTechnology:
    name: str
    category: str
    confidence: str
    evidence_source: str
    evidence_summary: str
    version: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    risk_hints: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        category = self.category if self.category in TECH_CATEGORIES else "unknown"
        confidence = self.confidence if self.confidence in CONFIDENCE_VALUES else "low"
        object.__setattr__(self, "name", _safe_text(self.name))
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "evidence_source", _safe_text(self.evidence_source))
        object.__setattr__(self, "evidence_summary", _safe_text(self.evidence_summary))
        object.__setattr__(self, "version", _safe_text(self.version))
        object.__setattr__(self, "tags", tuple(sorted({_safe_text(tag) for tag in self.tags})))
        object.__setattr__(self, "risk_hints", tuple(sorted({_safe_text(item) for item in self.risk_hints})))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class RiskHypothesis:
    hypothesis_id: str
    title: str
    rationale: str
    related_technology: str | None
    related_evidence_ids: tuple[str, ...]
    suggested_safe_next_step: str
    required_impact_level: str
    confidence: str
    status: str = "hypothesis"

    def __post_init__(self) -> None:
        confidence = self.confidence if self.confidence in CONFIDENCE_VALUES else "low"
        object.__setattr__(self, "title", _safe_text(self.title))
        object.__setattr__(self, "rationale", _safe_text(self.rationale))
        object.__setattr__(self, "related_technology", _safe_text(self.related_technology))
        object.__setattr__(self, "related_evidence_ids", tuple(sorted({_safe_text(item) for item in self.related_evidence_ids})))
        object.__setattr__(self, "suggested_safe_next_step", _safe_text(self.suggested_safe_next_step))
        object.__setattr__(self, "required_impact_level", _safe_text(self.required_impact_level))
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "status", "hypothesis")

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class TechnologyFingerprintInput:
    target: str
    normalized_target: str | None = None
    source_type: str = "supplied_metadata"
    headers: Mapping[str, Any] = field(default_factory=dict)
    final_url: str | None = None
    redirect_chain: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    content_type: str | None = None
    content_length: int | None = None
    capped_html_snippet: str | None = None
    script_src: tuple[str, ...] = field(default_factory=tuple)
    link_href: tuple[str, ...] = field(default_factory=tuple)
    meta_tags: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    endpoint_inventory: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at_utc: str | None = None

    def __post_init__(self) -> None:
        if not str(self.target).strip():
            raise ValueError("target is required")
        html = self.capped_html_snippet
        if html is not None and len(html.encode("utf-8", errors="ignore")) > MAX_HTML_SNIPPET_BYTES:
            html = html.encode("utf-8", errors="ignore")[:MAX_HTML_SNIPPET_BYTES].decode("utf-8", errors="ignore")
        object.__setattr__(self, "target", redact_target(self.target) or str(self.target))
        object.__setattr__(self, "normalized_target", redact_target(self.normalized_target))
        object.__setattr__(self, "headers", _safe_headers(self.headers)[0])
        object.__setattr__(self, "final_url", redact_target(self.final_url))
        object.__setattr__(self, "redirect_chain", tuple(redact_value(dict(item)) for item in self.redirect_chain))
        object.__setattr__(self, "capped_html_snippet", redact_value(html))
        object.__setattr__(self, "script_src", tuple(sorted({_safe_asset(item) for item in self.script_src if str(item).strip()})))
        object.__setattr__(self, "link_href", tuple(sorted({_safe_asset(item) for item in self.link_href if str(item).strip()})))
        object.__setattr__(self, "meta_tags", tuple(redact_value(dict(item)) for item in self.meta_tags))
        object.__setattr__(self, "endpoint_inventory", tuple(redact_value(dict(item)) for item in self.endpoint_inventory))
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))


@dataclass(frozen=True)
class TechnologyFingerprint:
    fingerprint_id: str
    created_at_utc: str
    target: str
    normalized_target: str | None
    source_type: str
    confidence: str
    detected_technologies: tuple[DetectedTechnology, ...] = field(default_factory=tuple)
    detected_frameworks: tuple[str, ...] = field(default_factory=tuple)
    detected_platforms: tuple[str, ...] = field(default_factory=tuple)
    detected_cdn_or_edge: tuple[str, ...] = field(default_factory=tuple)
    detected_hosting_hints: tuple[str, ...] = field(default_factory=tuple)
    detected_language_hints: tuple[str, ...] = field(default_factory=tuple)
    detected_security_controls: tuple[str, ...] = field(default_factory=tuple)
    detected_missing_controls: tuple[str, ...] = field(default_factory=tuple)
    asset_hints: tuple[str, ...] = field(default_factory=tuple)
    endpoint_hints: tuple[str, ...] = field(default_factory=tuple)
    admin_surface_hints: tuple[str, ...] = field(default_factory=tuple)
    api_surface_hints: tuple[str, ...] = field(default_factory=tuple)
    risk_hypotheses: tuple[RiskHypothesis, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "fingerprint_id": self.fingerprint_id,
                "created_at_utc": self.created_at_utc,
                "target": self.target,
                "normalized_target": self.normalized_target,
                "source_type": self.source_type,
                "confidence": self.confidence,
                "detected_technologies": [item.to_dict() for item in self.detected_technologies],
                "detected_frameworks": list(self.detected_frameworks),
                "detected_platforms": list(self.detected_platforms),
                "detected_cdn_or_edge": list(self.detected_cdn_or_edge),
                "detected_hosting_hints": list(self.detected_hosting_hints),
                "detected_language_hints": list(self.detected_language_hints),
                "detected_security_controls": list(self.detected_security_controls),
                "detected_missing_controls": list(self.detected_missing_controls),
                "asset_hints": list(self.asset_hints),
                "endpoint_hints": list(self.endpoint_hints),
                "admin_surface_hints": list(self.admin_surface_hints),
                "api_surface_hints": list(self.api_surface_hints),
                "risk_hypotheses": [item.to_dict() for item in self.risk_hypotheses],
                "evidence_ids": list(self.evidence_ids),
                "warnings": list(self.warnings),
                "redaction_applied": self.redaction_applied,
                "metadata": self.metadata,
            }
        )


def fingerprint_technology(payload: TechnologyFingerprintInput | Mapping[str, Any]) -> TechnologyFingerprint:
    data = payload if isinstance(payload, TechnologyFingerprintInput) else TechnologyFingerprintInput(**dict(payload))
    warnings: list[str] = []
    headers, headers_redacted = _safe_headers(data.headers)
    normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    if data.capped_html_snippet and len(str(data.capped_html_snippet).encode("utf-8", errors="ignore")) >= MAX_HTML_SNIPPET_BYTES:
        warnings.append("html_snippet_truncated_to_cap")
    html_signals = _extract_html_signals(data.capped_html_snippet or "")
    scripts = tuple(sorted(set(data.script_src + html_signals["script_src"])))
    links = tuple(sorted(set(data.link_href + html_signals["link_href"])))
    meta_tags = tuple(data.meta_tags + tuple(html_signals["meta_tags"]))
    technologies: list[DetectedTechnology] = []
    technologies.extend(_header_technologies(normalized_headers))
    technologies.extend(_html_technologies(data.capped_html_snippet or "", scripts, links, meta_tags))
    asset_hints = _asset_hints(scripts + links)
    endpoint_hints, admin_hints, api_hints = _surface_hints(data.endpoint_inventory)
    controls_present, controls_missing = _security_controls(normalized_headers)
    for control in controls_present:
        technologies.append(
            DetectedTechnology(
                name=control,
                category="security_control",
                confidence="high",
                evidence_source="headers",
                evidence_summary=f"{control} was present in supplied response headers.",
                tags=("security-control",),
            )
        )
    deduped = _dedupe_technologies(technologies)
    frameworks = _names_by_category(deduped, {"frontend_framework", "backend_framework", "cms"})
    platforms = _names_by_category(deduped, {"hosting", "web_server"})
    cdn_or_edge = _names_by_category(deduped, {"cdn"})
    hosting_hints = _names_by_category(deduped, {"hosting"})
    language_hints = _names_by_category(deduped, {"language"})
    evidence_ids = data.evidence_ids
    hypotheses = _risk_hypotheses(
        technologies=deduped,
        missing_controls=controls_missing,
        asset_hints=asset_hints,
        admin_surface_hints=admin_hints,
        api_surface_hints=api_hints,
        endpoint_hints=endpoint_hints,
        evidence_ids=evidence_ids,
    )
    confidence = _overall_confidence(deduped)
    created = data.created_at_utc or datetime.now(timezone.utc).isoformat()
    fingerprint_id = _stable_id(
        "fingerprint",
        data.normalized_target or data.target,
        [item.to_dict() for item in deduped],
        asset_hints,
        endpoint_hints,
        controls_missing,
    )
    return TechnologyFingerprint(
        fingerprint_id=fingerprint_id,
        created_at_utc=created,
        target=data.target,
        normalized_target=data.normalized_target or redact_target(data.final_url) or data.target,
        source_type=_safe_text(data.source_type),
        confidence=confidence,
        detected_technologies=tuple(deduped),
        detected_frameworks=frameworks,
        detected_platforms=platforms,
        detected_cdn_or_edge=cdn_or_edge,
        detected_hosting_hints=hosting_hints,
        detected_language_hints=language_hints,
        detected_security_controls=tuple(sorted(controls_present)),
        detected_missing_controls=tuple(sorted(controls_missing)),
        asset_hints=asset_hints,
        endpoint_hints=endpoint_hints,
        admin_surface_hints=admin_hints,
        api_surface_hints=api_hints,
        risk_hypotheses=tuple(hypotheses),
        evidence_ids=evidence_ids,
        warnings=tuple(warnings),
        redaction_applied=bool(headers_redacted or canonical_json(redact_value(data.metadata)) != canonical_json(data.metadata)),
        metadata={
            "content_type": _safe_text(data.content_type),
            "content_length": data.content_length,
            "html_snippet_stored": False,
            "script_src_count": len(scripts),
            "link_href_count": len(links),
            "endpoint_inventory_count": len(data.endpoint_inventory),
        },
    )


def fingerprint_from_fetch_result(fetch_result: Any, **extra: Any) -> TechnologyFingerprint:
    payload = fetch_result.to_dict() if hasattr(fetch_result, "to_dict") else dict(fetch_result)
    return fingerprint_technology(
        TechnologyFingerprintInput(
            target=str(payload.get("target", "")),
            normalized_target=payload.get("normalized_target"),
            source_type="safe_http_fetch",
            headers=payload.get("headers", {}),
            final_url=payload.get("final_url"),
            redirect_chain=tuple(payload.get("redirect_chain", [])),
            content_type=payload.get("content_type"),
            content_length=payload.get("content_length"),
            capped_html_snippet=extra.get("capped_html_snippet"),
            script_src=tuple(extra.get("script_src", [])),
            link_href=tuple(extra.get("link_href", [])),
            meta_tags=tuple(extra.get("meta_tags", [])),
            endpoint_inventory=tuple(extra.get("endpoint_inventory", [])),
            evidence_ids=tuple(extra.get("evidence_ids", [])),
            created_at_utc=extra.get("created_at_utc"),
            metadata=extra.get("metadata", {}),
        )
    )


def evidence_from_fingerprint(fingerprint: TechnologyFingerprint, *, related_adapter_id: str | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.TECHNOLOGY_FINGERPRINT,
        source_id=fingerprint.fingerprint_id,
        target=fingerprint.target,
        normalized_target=fingerprint.normalized_target,
        title="Passive technology fingerprint",
        summary=(
            f"Detected {len(fingerprint.detected_technologies)} technology hint(s), "
            f"{len(fingerprint.asset_hints)} asset hint(s), and {len(fingerprint.risk_hypotheses)} risk hypothesis item(s)."
        ),
        structured_data=fingerprint.to_dict(),
        tags=("technology-fingerprint", "passive", "no-network"),
        confidence=fingerprint.confidence,
        related_adapter_id=related_adapter_id,
        redaction_applied=True,
    )


def findings_from_fingerprint(_fingerprint: TechnologyFingerprint, _evidence: EvidenceRecord | None = None) -> list[Any]:
    return []


def _header_technologies(headers: Mapping[str, str]) -> list[DetectedTechnology]:
    detections: list[DetectedTechnology] = []
    server = headers.get("server")
    if server:
        detections.append(_tech(_server_name(server), "web_server", "high", "header:server", "Server header was supplied.", version=_version_from(server), tags=("disclosure", "server")))
    powered = headers.get("x-powered-by")
    if powered:
        lowered = powered.lower()
        if "next" in lowered:
            detections.append(_tech("Next.js", "frontend_framework", "high", "header:x-powered-by", "X-Powered-By explicitly referenced Next.js.", tags=("nextjs", "framework")))
        elif "express" in lowered:
            detections.append(_tech("Express", "backend_framework", "high", "header:x-powered-by", "X-Powered-By explicitly referenced Express.", tags=("express", "framework")))
            detections.append(_tech("Node.js", "language", "medium", "header:x-powered-by", "Express usually indicates a Node.js application stack.", tags=("nodejs", "language")))
        else:
            detections.append(_tech(powered, "backend_framework", "medium", "header:x-powered-by", "X-Powered-By header disclosed a platform/framework hint.", tags=("disclosure",)))
    if "cf-ray" in headers or "cf-cache-status" in headers or "server" in headers and "cloudflare" in headers["server"].lower():
        detections.append(_tech("Cloudflare", "cdn", "high", "headers", "Cloudflare-specific response headers were supplied.", tags=("cdn", "edge")))
    if any(key.startswith("x-vercel") for key in headers) or headers.get("server", "").lower() == "vercel":
        detections.append(_tech("Vercel", "hosting", "high", "headers", "Vercel-specific response headers were supplied.", tags=("hosting", "edge")))
    if "x-nextjs-cache" in headers:
        detections.append(_tech("Next.js", "frontend_framework", "high", "header:x-nextjs-cache", "Next.js cache header was supplied.", tags=("nextjs", "framework")))
    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        detections.append(_tech("ASP.NET", "backend_framework", "high", "headers", "ASP.NET-specific response headers were supplied.", tags=("dotnet", "framework")))
    if "x-runtime" in headers:
        detections.append(_tech(headers["x-runtime"], "backend_framework", "low", "header:x-runtime", "X-Runtime header supplied a framework/runtime hint.", tags=("runtime",)))
    if "via" in headers:
        detections.append(_tech("Proxy/CDN via header", "cdn", "medium", "header:via", "Via header indicates an intermediary or edge layer.", tags=("proxy", "edge")))
    if "report-to" in headers or "nel" in headers:
        detections.append(_tech("Network Error Logging", "security_control", "medium", "headers", "Report-To or NEL headers were supplied.", tags=("nel", "reporting")))
    return detections


def _html_technologies(html: str, scripts: tuple[str, ...], links: tuple[str, ...], meta_tags: tuple[Mapping[str, Any], ...]) -> list[DetectedTechnology]:
    detections: list[DetectedTechnology] = []
    lowered = html.lower()
    if "__next_data__" in lowered or any("/_next/" in item.lower() for item in scripts + links):
        detections.append(_tech("Next.js", "frontend_framework", "high", "html/assets", "Next.js markers were supplied in HTML or asset paths.", tags=("nextjs", "frontend")))
    if "__nuxt" in lowered or any("/_nuxt/" in item.lower() for item in scripts + links):
        detections.append(_tech("Nuxt", "frontend_framework", "high", "html/assets", "Nuxt markers were supplied in HTML or asset paths.", tags=("nuxt", "frontend")))
    if "astro-island" in lowered or any("/_astro/" in item.lower() for item in scripts + links):
        detections.append(_tech("Astro", "frontend_framework", "high", "html/assets", "Astro markers were supplied in HTML or asset paths.", tags=("astro", "frontend")))
    if any("vite" in item.lower() for item in scripts + links) or "/@vite/" in lowered:
        detections.append(_tech("Vite", "build_tool", "medium", "assets", "Vite-style asset markers were supplied.", tags=("vite", "build")))
    if "data-sveltekit" in lowered or any("_app/immutable" in item.lower() for item in scripts + links):
        detections.append(_tech("SvelteKit", "frontend_framework", "high", "html/assets", "SvelteKit markers were supplied.", tags=("sveltekit", "frontend")))
    if 'id="root"' in lowered or 'id="app"' in lowered:
        detections.append(_tech("Client-side JavaScript app root", "frontend_framework", "low", "html", "HTML contained a common JavaScript application root marker.", tags=("frontend", "spa")))
    for item in meta_tags:
        name = str(item.get("name") or item.get("property") or "").lower()
        content = str(item.get("content") or "")
        if name == "generator" and content:
            category = "cms" if any(part in content.lower() for part in ("wordpress", "drupal", "joomla")) else "unknown"
            detections.append(_tech(content, category, "high", "meta:generator", "Meta generator tag was supplied.", tags=("generator",)))
    if any("googletagmanager" in item.lower() or "google-analytics" in item.lower() for item in scripts):
        detections.append(_tech("Google Analytics/Tag Manager", "analytics", "medium", "script_src", "Analytics script path was supplied.", tags=("analytics",)))
    return detections


def _extract_html_signals(html: str) -> dict[str, tuple[Any, ...]]:
    if not html:
        return {"script_src": (), "link_href": (), "meta_tags": ()}
    snippet = html.encode("utf-8", errors="ignore")[:MAX_HTML_SNIPPET_BYTES].decode("utf-8", errors="ignore")
    script_src = tuple(_safe_asset(match.group(1)) for match in re.finditer(r"(?is)<script[^>]+src=[\"']([^\"']+)[\"']", snippet))
    link_href = tuple(_safe_asset(match.group(1)) for match in re.finditer(r"(?is)<link[^>]+href=[\"']([^\"']+)[\"']", snippet))
    meta_tags: list[dict[str, str]] = []
    for match in re.finditer(r"(?is)<meta\s+([^>]+)>", snippet):
        attrs = dict((key.lower(), value) for key, value in re.findall(r"([A-Za-z_:.-]+)=[\"']([^\"']*)[\"']", match.group(1)))
        if attrs:
            meta_tags.append(redact_value(attrs))
    return {"script_src": script_src, "link_href": link_href, "meta_tags": tuple(meta_tags)}


def _asset_hints(paths: tuple[str, ...]) -> tuple[str, ...]:
    hints: set[str] = set()
    for path in paths:
        lowered = path.lower()
        if "/_next/" in lowered:
            hints.add("nextjs_asset_path")
        if "/_nuxt/" in lowered:
            hints.add("nuxt_asset_path")
        if "/_astro/" in lowered:
            hints.add("astro_asset_path")
        if "vite" in lowered or "/assets/" in lowered:
            hints.add("frontend_asset_bundle")
        if "webpack" in lowered or "chunk" in lowered or "/static/js/" in lowered:
            hints.add("javascript_bundle_or_chunk")
        if lowered.endswith(".map") or ".map?" in lowered:
            hints.add("source_map_reference_hint")
    return tuple(sorted(hints))


def _surface_hints(endpoints: tuple[Mapping[str, Any], ...]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    endpoint_hints: set[str] = set()
    admin_hints: set[str] = set()
    api_hints: set[str] = set()
    for item in endpoints:
        path = str(item.get("path") or item.get("normalized_url") or item.get("url") or "")
        lowered = path.lower()
        for part in SURFACE_PARTS:
            if part in lowered:
                endpoint_hints.add(f"path_hint:{part}")
        if any(part in lowered for part in ("admin", "dashboard", "login", "auth", "account", "billing", "upload")):
            admin_hints.add(redact_target(path) or path)
        if any(part in lowered for part in ("api", "graphql")):
            api_hints.add(redact_target(path) or path)
        auth_indicators = item.get("auth_indicators") or []
        risk_hints = item.get("risk_hints") or []
        if auth_indicators:
            endpoint_hints.add("auth_indicators_present")
        if risk_hints:
            endpoint_hints.update(str(hint) for hint in risk_hints)
    return tuple(sorted(endpoint_hints)), tuple(sorted(admin_hints)), tuple(sorted(api_hints))


def _security_controls(headers: Mapping[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    present = tuple(sorted(label for key, label in SECURITY_HEADERS.items() if key in headers))
    missing = tuple(sorted(label for key, label in SECURITY_HEADERS.items() if key not in headers))
    return present, missing


def _risk_hypotheses(
    *,
    technologies: tuple[DetectedTechnology, ...],
    missing_controls: tuple[str, ...],
    asset_hints: tuple[str, ...],
    admin_surface_hints: tuple[str, ...],
    api_surface_hints: tuple[str, ...],
    endpoint_hints: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> list[RiskHypothesis]:
    names = {item.name.lower() for item in technologies}
    hypotheses: list[RiskHypothesis] = []
    if "Content-Security-Policy" in missing_controls and any(name in names for name in ("next.js", "nuxt", "astro", "sveltekit", "client-side javascript app root")):
        hypotheses.append(_hypothesis("missing_csp_frontend_app", "Missing CSP on frontend application", "Frontend application hints were supplied while CSP was absent.", "frontend_app", evidence_ids, "Review supplied headers and consider adding a restrictive CSP; do not run active validation without approval.", "green", "medium"))
    if ("X-Frame-Options" in missing_controls and "Content-Security-Policy" in missing_controls) and admin_surface_hints:
        hypotheses.append(_hypothesis("clickjacking_admin_surface", "Clickjacking controls absent with admin/auth surface hints", "Supplied paths suggest authenticated or administrative surfaces while frame controls were absent.", None, evidence_ids, "Confirm intended framing policy with the owner before any active testing.", "green", "medium"))
    if any("disclosure" in item.tags for item in technologies):
        hypotheses.append(_hypothesis("technology_disclosure", "Technology disclosure may help prioritization", "Supplied headers disclosed server or platform technology hints.", None, evidence_ids, "Use disclosed technology only for defensive inventory and version review.", "green", "low"))
    if "source_map_reference_hint" in asset_hints:
        hypotheses.append(_hypothesis("source_map_reference", "Source map reference supplied", "Supplied asset paths referenced source maps; accessibility was not tested.", None, evidence_ids, "Only verify source map accessibility in a future explicitly approved low-impact check.", "green", "low"))
    if api_surface_hints and "auth_indicators_present" not in endpoint_hints:
        hypotheses.append(_hypothesis("api_surface_auth_review", "API surface hint needs authorization review", "Supplied endpoint inventory included API-like paths without clear auth indicators.", None, evidence_ids, "Review imported API metadata for intended authentication before active validation.", "green", "medium"))
    if admin_surface_hints:
        hypotheses.append(_hypothesis("admin_surface_review", "Admin/login surface hint", "Supplied endpoint paths indicate admin, auth, login, account, billing, or upload surfaces.", None, evidence_ids, "Keep any future checks scoped and approval-gated; do not probe paths automatically.", "green", "low"))
    return hypotheses


def _hypothesis(identifier: str, title: str, rationale: str, technology: str | None, evidence_ids: tuple[str, ...], next_step: str, impact: str, confidence: str) -> RiskHypothesis:
    return RiskHypothesis(
        hypothesis_id=_stable_id("hypothesis", identifier, title, evidence_ids),
        title=title,
        rationale=rationale,
        related_technology=technology,
        related_evidence_ids=evidence_ids,
        suggested_safe_next_step=next_step,
        required_impact_level=impact,
        confidence=confidence,
    )


def _safe_headers(headers: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    safe: dict[str, Any] = {}
    redacted = False
    for key, value in headers.items():
        name = str(key)
        lowered = name.lower()
        if lowered in SENSITIVE_HEADER_NAMES or any(part in lowered for part in ("token", "secret", "session")):
            safe[name] = "<redacted>"
            redacted = True
        else:
            scrubbed = redact_value(value)
            if scrubbed != value:
                redacted = True
            safe[name] = scrubbed
    return safe, redacted


def _dedupe_technologies(items: list[DetectedTechnology]) -> tuple[DetectedTechnology, ...]:
    by_key: dict[tuple[str, str], DetectedTechnology] = {}
    rank = {"low": 0, "medium": 1, "high": 2}
    for item in items:
        key = (item.name.lower(), item.category)
        existing = by_key.get(key)
        if existing is None or rank[item.confidence] > rank[existing.confidence]:
            by_key[key] = item
    return tuple(sorted(by_key.values(), key=lambda item: (item.category, item.name.lower())))


def _names_by_category(items: tuple[DetectedTechnology, ...], categories: set[str]) -> tuple[str, ...]:
    return tuple(sorted({item.name for item in items if item.category in categories}))


def _overall_confidence(items: tuple[DetectedTechnology, ...]) -> str:
    values = {item.confidence for item in items}
    if "high" in values:
        return "high"
    if "medium" in values:
        return "medium"
    return "low"


def _tech(name: str, category: str, confidence: str, evidence_source: str, evidence_summary: str, *, version: str | None = None, tags: tuple[str, ...] = (), risk_hints: tuple[str, ...] = ()) -> DetectedTechnology:
    return DetectedTechnology(name=name, category=category, confidence=confidence, evidence_source=evidence_source, evidence_summary=evidence_summary, version=version, tags=tags, risk_hints=risk_hints)


def _server_name(value: str) -> str:
    return str(value).split("/", 1)[0].strip() or "Server header"


def _version_from(value: str) -> str | None:
    match = re.search(r"/([0-9][A-Za-z0-9._-]*)", str(value))
    return match.group(1) if match else None


def _safe_asset(value: Any) -> str:
    raw = str(redact_value(str(value))).strip()
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.netloc:
        return redact_target(raw) or raw
    return redact_value(raw)


def _safe_text(value: Any) -> Any:
    if value is None:
        return None
    return redact_value(str(value))


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()[:24]
