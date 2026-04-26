from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from aegis_ev.audit import canonical_json, redact_target, redact_value
from aegis_ev.evidence import EvidenceRecord, EvidenceSourceType, EvidenceType, FindingConfidence


HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
SECRET_PARTS = ("api_key", "apikey", "authorization", "cookie", "password", "secret", "session", "token")
SENSITIVE_PATH_PARTS = ("admin", "auth", "billing", "card", "login", "oauth", "password", "payment", "session", "user")


class ApiImportSourceType(str, Enum):
    OPENAPI = "openapi"
    POSTMAN = "postman"
    HAR = "har"
    MANUAL = "manual"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EndpointInventory:
    endpoint_id: str
    source_type: ApiImportSourceType | str
    source_id: str
    method: str
    path: str
    url: str | None = None
    normalized_url: str | None = None
    host: str | None = None
    scheme: str | None = None
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    parameters_summary: str = ""
    request_body_summary: str = ""
    response_summary: str = ""
    auth_indicators: tuple[str, ...] = field(default_factory=tuple)
    sensitive_indicators: tuple[str, ...] = field(default_factory=tuple)
    risk_hints: tuple[str, ...] = field(default_factory=tuple)
    evidence_id: str | None = None
    redaction_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        source_type = _source_type_value(self.source_type)
        safe_url = _safe_url(self.url)
        safe_normalized = _safe_url(self.normalized_url)
        safe_path = _safe_path(self.path)
        safe_metadata = redact_value(self.metadata)
        redaction_applied = (
            safe_url != self.url
            or safe_normalized != self.normalized_url
            or safe_path != self.path
            or canonical_json(safe_metadata) != canonical_json(redact_value(self.metadata))
            or self.redaction_applied
        )
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(self, "path", safe_path)
        object.__setattr__(self, "url", safe_url)
        object.__setattr__(self, "normalized_url", safe_normalized)
        object.__setattr__(self, "operation_id", redact_value(self.operation_id))
        object.__setattr__(self, "summary", redact_value(self.summary))
        object.__setattr__(self, "description", redact_value(self.description))
        object.__setattr__(self, "tags", tuple(sorted({str(item) for item in self.tags})))
        object.__setattr__(self, "auth_indicators", tuple(sorted({str(item) for item in self.auth_indicators})))
        object.__setattr__(self, "sensitive_indicators", tuple(sorted({str(item) for item in self.sensitive_indicators})))
        object.__setattr__(self, "risk_hints", tuple(sorted({str(item) for item in self.risk_hints})))
        object.__setattr__(self, "metadata", safe_metadata)
        object.__setattr__(self, "redaction_applied", redaction_applied)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class ImportResult:
    import_id: str
    source_type: ApiImportSourceType | str
    source_name: str | None
    created_at_utc: str
    endpoint_count: int
    endpoints: tuple[EndpointInventory, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    redaction_applied: bool = False
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        source_type = _source_type_value(self.source_type)
        endpoints = tuple(self.endpoints)
        metadata = redact_value(self.metadata)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "endpoints", endpoints)
        object.__setattr__(self, "endpoint_count", len(endpoints))
        object.__setattr__(self, "warnings", tuple(str(item) for item in self.warnings))
        object.__setattr__(self, "errors", tuple(str(item) for item in self.errors))
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(
            self,
            "redaction_applied",
            bool(self.redaction_applied or any(endpoint.redaction_applied for endpoint in endpoints)),
        )

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "import_id": self.import_id,
                "source_type": self.source_type,
                "source_name": self.source_name,
                "created_at_utc": self.created_at_utc,
                "endpoint_count": self.endpoint_count,
                "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "redaction_applied": self.redaction_applied,
                "evidence_ids": list(self.evidence_ids),
                "metadata": self.metadata,
            }
        )


def import_openapi(data: dict[str, Any], *, source_name: str | None = None, now: datetime | None = None) -> ImportResult:
    _require_object(data, "OpenAPI input")
    warnings: list[str] = []
    errors: list[str] = []
    endpoints: list[EndpointInventory] = []
    if not isinstance(data.get("paths"), dict):
        errors.append("OpenAPI JSON must contain an object at paths")
        return _result(ApiImportSourceType.OPENAPI, source_name, endpoints, warnings, errors, now)
    if "swagger" in data:
        warnings.append("Swagger/OpenAPI 2.0 input is parsed using basic path and method extraction only")
    for ref in _collect_refs(data):
        if str(ref).startswith(("http://", "https://")):
            warnings.append("Remote $ref ignored; no network fetch was performed")
    global_auth = _openapi_auth_indicators(data)
    for path in sorted(data["paths"]):
        path_item = data["paths"][path]
        if not isinstance(path_item, dict):
            warnings.append(f"Ignored non-object path item: {path}")
            continue
        shared_parameters = path_item.get("parameters", [])
        for method in sorted(key for key in path_item if key.lower() in HTTP_METHODS):
            operation = path_item.get(method, {})
            if not isinstance(operation, dict):
                warnings.append(f"Ignored non-object operation: {method.upper()} {path}")
                continue
            auth_indicators = _operation_auth_indicators(operation, global_auth)
            sensitive_indicators = _sensitive_indicators(path, operation)
            endpoints.append(
                EndpointInventory(
                    endpoint_id=_endpoint_id(ApiImportSourceType.OPENAPI.value, method.upper(), path),
                    source_type=ApiImportSourceType.OPENAPI,
                    source_id=str(operation.get("operationId") or f"{method.upper()} {path}"),
                    method=method.upper(),
                    path=path,
                    operation_id=_optional_string(operation.get("operationId")),
                    summary=_optional_string(operation.get("summary")),
                    description=_optional_string(operation.get("description")),
                    tags=tuple(str(item) for item in operation.get("tags", []) if item is not None),
                    parameters_summary=_summarize_openapi_parameters(shared_parameters, operation.get("parameters", [])),
                    request_body_summary=_summarize_request_body(operation.get("requestBody")),
                    response_summary=_summarize_responses(operation.get("responses")),
                    auth_indicators=tuple(auth_indicators),
                    sensitive_indicators=tuple(sensitive_indicators),
                    risk_hints=tuple(_risk_hints(path, auth_indicators)),
                    metadata={"deprecated": bool(operation.get("deprecated", False))},
                )
            )
    return _result(ApiImportSourceType.OPENAPI, source_name or _openapi_title(data), endpoints, warnings, errors, now)


def import_postman(data: dict[str, Any], *, source_name: str | None = None, now: datetime | None = None) -> ImportResult:
    _require_object(data, "Postman input")
    warnings: list[str] = []
    errors: list[str] = []
    endpoints: list[EndpointInventory] = []
    items = data.get("item")
    if not isinstance(items, list):
        errors.append("Postman collection JSON must contain an item list")
        return _result(ApiImportSourceType.POSTMAN, source_name, endpoints, warnings, errors, now)
    collection_auth = _postman_auth(data.get("auth"))
    _walk_postman_items(items, endpoints, warnings, collection_auth=collection_auth)
    name = source_name or _optional_string((data.get("info") or {}).get("name"))
    return _result(ApiImportSourceType.POSTMAN, name, endpoints, warnings, errors, now)


def import_har(data: dict[str, Any], *, source_name: str | None = None, now: datetime | None = None) -> ImportResult:
    _require_object(data, "HAR input")
    warnings: list[str] = []
    errors: list[str] = []
    endpoints_by_key: dict[tuple[str, str], EndpointInventory] = {}
    entries = ((data.get("log") or {}).get("entries") if isinstance(data.get("log"), dict) else None)
    if not isinstance(entries, list):
        errors.append("HAR JSON must contain log.entries list")
        return _result(ApiImportSourceType.HAR, source_name, [], warnings, errors, now)
    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            warnings.append("Ignored HAR entry without a request object")
            continue
        method = str(request.get("method", "GET")).upper()
        raw_url = str(request.get("url", ""))
        normalized_url, scheme, host, path = _normalize_url_parts(raw_url)
        dedupe_key = (method, normalized_url or path)
        if dedupe_key in endpoints_by_key:
            continue
        header_names = _names_from_items(request.get("headers", []))
        cookie_names = _names_from_items(request.get("cookies", []))
        query_names = _query_names(raw_url, request.get("queryString", []))
        auth_indicators = tuple(name for name in header_names if _is_secret_name(name))
        sensitive = tuple(sorted(set(cookie_names + tuple(name for name in query_names if _is_secret_name(name)))))
        body_summary = "present redacted" if request.get("postData") else ""
        endpoints_by_key[dedupe_key] = EndpointInventory(
            endpoint_id=_endpoint_id(ApiImportSourceType.HAR.value, method, normalized_url or path),
            source_type=ApiImportSourceType.HAR,
            source_id=f"{method} {normalized_url or path}",
            method=method,
            path=path,
            url=raw_url,
            normalized_url=normalized_url,
            host=host,
            scheme=scheme,
            parameters_summary=_summary("query", query_names),
            request_body_summary=body_summary,
            auth_indicators=auth_indicators,
            sensitive_indicators=sensitive,
            risk_hints=tuple(_risk_hints(path, auth_indicators)),
            metadata={"header_names": header_names, "cookie_names": cookie_names},
        )
    return _result(ApiImportSourceType.HAR, source_name or "HAR Import", list(endpoints_by_key.values()), warnings, errors, now)


def evidence_from_import_result(result: ImportResult, *, evidence_id: str | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id or f"evidence_import_{result.import_id}",
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.API_IMPORT,
        source_id=result.import_id,
        title=f"API import: {result.source_type}",
        summary=f"Imported {result.endpoint_count} endpoint(s) from {result.source_type}",
        structured_data=result.to_dict(),
        tags=("api-import", result.source_type),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def _result(
    source_type: ApiImportSourceType,
    source_name: str | None,
    endpoints: list[EndpointInventory],
    warnings: list[str],
    errors: list[str],
    now: datetime | None,
) -> ImportResult:
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    import_id = _import_id(source_type.value, source_name, endpoints)
    return ImportResult(
        import_id=import_id,
        source_type=source_type,
        source_name=source_name,
        created_at_utc=timestamp,
        endpoint_count=len(endpoints),
        endpoints=tuple(sorted(endpoints, key=lambda item: item.endpoint_id)),
        warnings=tuple(warnings),
        errors=tuple(errors),
        metadata={"schema_version": "api-import.v1"},
    )


def _endpoint_id(source_type: str, method: str, normalized: str) -> str:
    return "endpoint_" + hashlib.sha256(f"{source_type}:{method.upper()}:{normalized}".encode("utf-8")).hexdigest()[:24]


def _import_id(source_type: str, source_name: str | None, endpoints: list[EndpointInventory]) -> str:
    payload = {
        "source_name": source_name or "",
        "source_type": source_type,
        "endpoints": [endpoint.endpoint_id for endpoint in sorted(endpoints, key=lambda item: item.endpoint_id)],
    }
    return "import_" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:24]


def _safe_url(value: str | None) -> str | None:
    return redact_target(value) if value else value


def _safe_path(value: str) -> str:
    if not value:
        return value
    if "://" in value:
        return redact_target(value) or "<invalid-target>"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return redact_value(value)
    return urlunsplit(("", "", parsed.path or value.split("?", 1)[0], "", ""))


def _normalize_url_parts(raw_url: str) -> tuple[str | None, str | None, str | None, str]:
    safe_url = redact_target(raw_url)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return safe_url, None, None, redact_value(raw_url)
    path = parsed.path or "/"
    normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))
    return redact_target(normalized), parsed.scheme.lower() or None, parsed.hostname, path


def _query_names(raw_url: str, query_items: Any) -> tuple[str, ...]:
    names = [key for key, _value in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True)]
    names.extend(_names_from_items(query_items))
    return tuple(sorted(set(names)))


def _names_from_items(items: Any) -> tuple[str, ...]:
    if not isinstance(items, list):
        return ()
    names = []
    for item in items:
        if isinstance(item, dict) and item.get("name") is not None:
            names.append(str(item["name"]))
    return tuple(sorted(set(names)))


def _openapi_title(data: dict[str, Any]) -> str | None:
    info = data.get("info")
    if isinstance(info, dict) and info.get("title") is not None:
        return str(info["title"])
    return None


def _openapi_auth_indicators(data: dict[str, Any]) -> tuple[str, ...]:
    schemes = ((data.get("components") or {}).get("securitySchemes") if isinstance(data.get("components"), dict) else None)
    if not isinstance(schemes, dict):
        return ()
    return tuple(sorted(str(name) for name in schemes))


def _operation_auth_indicators(operation: dict[str, Any], global_auth: tuple[str, ...]) -> tuple[str, ...]:
    security = operation.get("security")
    if security == []:
        return ()
    if isinstance(security, list):
        names = []
        for item in security:
            if isinstance(item, dict):
                names.extend(str(name) for name in item)
        return tuple(sorted(set(names)))
    return global_auth


def _summarize_openapi_parameters(*parameter_groups: Any) -> str:
    names = []
    for group in parameter_groups:
        if isinstance(group, list):
            for item in group:
                if isinstance(item, dict) and item.get("name") is not None:
                    location = item.get("in", "unknown")
                    names.append(f"{location}:{item['name']}")
    return _summary("parameters", names)


def _summarize_request_body(request_body: Any) -> str:
    if not isinstance(request_body, dict):
        return ""
    content = request_body.get("content")
    if isinstance(content, dict):
        return _summary("request content-types", content.keys())
    return "request body present"


def _summarize_responses(responses: Any) -> str:
    if not isinstance(responses, dict):
        return ""
    return _summary("response status", responses.keys())


def _postman_auth(auth_payload: Any) -> tuple[str, ...]:
    if isinstance(auth_payload, dict) and auth_payload.get("type") is not None:
        return (str(auth_payload["type"]),)
    return ()


def _walk_postman_items(
    items: list[Any],
    endpoints: list[EndpointInventory],
    warnings: list[str],
    *,
    collection_auth: tuple[str, ...],
) -> None:
    for item in items:
        if not isinstance(item, dict):
            warnings.append("Ignored non-object Postman item")
            continue
        events = item.get("event")
        if isinstance(events, list) and events:
            warnings.append("Postman scripts were observed and ignored; no script execution was performed")
        children = item.get("item")
        if isinstance(children, list):
            _walk_postman_items(children, endpoints, warnings, collection_auth=collection_auth)
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET")).upper()
        raw_url = _postman_url(request.get("url"))
        normalized_url, scheme, host, path = _normalize_url_parts(raw_url)
        header_names = _postman_header_names(request.get("header"))
        auth_indicators = _postman_auth(request.get("auth")) or collection_auth
        body_summary = _postman_body_summary(request.get("body"))
        endpoints.append(
            EndpointInventory(
                endpoint_id=_endpoint_id(ApiImportSourceType.POSTMAN.value, method, normalized_url or path),
                source_type=ApiImportSourceType.POSTMAN,
                source_id=str(item.get("name") or f"{method} {path}"),
                method=method,
                path=path,
                url=raw_url,
                normalized_url=normalized_url,
                host=host,
                scheme=scheme,
                summary=_optional_string(item.get("name")),
                request_body_summary=body_summary,
                auth_indicators=auth_indicators,
                sensitive_indicators=tuple(name for name in header_names if _is_secret_name(name)),
                risk_hints=tuple(_risk_hints(path, auth_indicators)),
                metadata={"header_names": header_names},
            )
        )


def _postman_url(url_payload: Any) -> str:
    if isinstance(url_payload, str):
        return url_payload
    if not isinstance(url_payload, dict):
        return ""
    if url_payload.get("raw") is not None:
        return str(url_payload["raw"])
    protocol = str(url_payload.get("protocol") or "https")
    host = ".".join(str(part) for part in url_payload.get("host", []) if part is not None)
    path = "/".join(str(part) for part in url_payload.get("path", []) if part is not None)
    return f"{protocol}://{host}/{path}" if host else "/" + path


def _postman_header_names(headers: Any) -> tuple[str, ...]:
    if not isinstance(headers, list):
        return ()
    return tuple(sorted({str(item["key"]) for item in headers if isinstance(item, dict) and item.get("key") is not None}))


def _postman_body_summary(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    mode = body.get("mode")
    if mode is None:
        return "request body present"
    return f"request body mode: {mode}"


def _collect_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                refs.append(item)
            else:
                refs.extend(_collect_refs(item))
    elif isinstance(value, list):
        for item in value:
            refs.extend(_collect_refs(item))
    return refs


def _sensitive_indicators(path: str, operation: dict[str, Any]) -> tuple[str, ...]:
    text = " ".join(
        [
            path,
            str(operation.get("operationId", "")),
            str(operation.get("summary", "")),
            str(operation.get("description", "")),
        ]
    ).lower()
    return tuple(sorted({part for part in SENSITIVE_PATH_PARTS if part in text}))


def _risk_hints(path: str, auth_indicators: tuple[str, ...]) -> list[str]:
    hints = []
    lowered = path.lower()
    if any(part in lowered for part in ("admin", "auth", "account", "billing", "payment")):
        hints.append("sensitive_path_indicator")
        if not auth_indicators:
            hints.append("missing_auth_indicator_for_sensitive_path")
    if "deprecated" in lowered or "/v1/" in lowered:
        hints.append("deprecated_or_legacy_path_indicator")
    return hints


def _is_secret_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return any(part in normalized for part in SECRET_PARTS)


def _summary(label: str, values: Any) -> str:
    items = tuple(sorted(str(value) for value in values if value is not None))
    return f"{label}: {', '.join(items)}" if items else ""


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(redact_value(str(value)))


def _source_type_value(value: ApiImportSourceType | str) -> str:
    try:
        return ApiImportSourceType(value).value
    except ValueError as exc:
        raise ValueError(f"invalid source_type: {value}") from exc


def _require_object(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
