from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json
import hashlib
import os

from aegis_ev.audit import redact_value, redact_target
from aegis_ev.evidence import EvidenceRecord, EvidenceType, EvidenceSourceType
from aegis_ev.models import Evidence, Finding


@dataclass
class EndpointInventory:
    """Structured endpoint inventory object for API import functionality."""
    endpoint_id: str
    source_type: str  # openapi, postman, har, manual, unknown
    source_id: str
    method: str
    path: str
    url: Optional[str] = None
    normalized_url: Optional[str] = None
    host: Optional[str] = None
    scheme: Optional[str] = None
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    parameters_summary: str = ""
    request_body_summary: str = ""
    response_summary: str = ""
    auth_indicators: List[str] = field(default_factory=list)
    sensitive_indicators: List[str] = field(default_factory=list)
    risk_hints: List[str] = field(default_factory=list)
    evidence_id: Optional[str] = None
    redaction_applied: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportResult:
    """Structured import result from API import operations."""
    import_id: str
    source_type: str
    source_name: Optional[str]
    created_at_utc: str
    endpoint_count: int
    endpoints: List[EndpointInventory]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    redaction_applied: bool = False
    evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ApiImport:
    """API import foundation for OpenAPI/Postman/HAR files."""
    
    @staticmethod
    def _generate_endpoint_id(method: str, path: str, source: str) -> str:
        """Generate deterministic endpoint ID."""
        data = f"{method}:{path}:{source}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    @staticmethod
    def import_openapi(openapi_spec: Dict[str, Any]) -> ImportResult:
        """Import OpenAPI 3.x JSON specification."""
        endpoints = []
        warnings = []
        errors = []
        
        try:
            # Process OpenAPI paths
            paths = openapi_spec.get('paths', {})
            for path, path_item in paths.items():
                for method in path_item.keys():
                    if method.startswith('x-') or method == 'parameters':
                        continue
                    
                    # Create endpoint inventory
                    endpoint = EndpointInventory(
                        endpoint_id=ApiImport._generate_endpoint_id(method, path, 'openapi'),
                        source_type='openapi',
                        source_id='openapi_import',
                        method=method.upper(),
                        path=path,
                        summary=path_item.get(method, {}).get('summary', ''),
                        description=path_item.get(method, {}).get('description', ''),
                        tags=path_item.get(method, {}).get('tags', []),
                        auth_indicators=ApiImport._extract_openapi_auth_indicators(openapi_spec, path, method)
                    )
                    endpoints.append(endpoint)
            
            return ImportResult(
                import_id=ApiImport._generate_endpoint_id('openapi', str(len(openapi_spec)), 'openapi'),
                source_type='openapi',
                source_name='OpenAPI Import',
                created_at_utc="2026-01-01T00:00:00Z",
                endpoint_count=len(endpoints),
                endpoints=endpoints,
                warnings=warnings,
                errors=errors
            )
        except Exception as e:
            errors.append(f"Failed to parse OpenAPI spec: {str(e)}")
            return ImportResult(
                import_id="",
                source_type='openapi',
                source_name=None,
                created_at_utc="",
                endpoint_count=0,
                endpoints=[],
                warnings=[],
                errors=errors
            )
    
    @staticmethod
    def _extract_openapi_auth_indicators(openapi_spec: Dict[str, Any], path: str, method: str) -> List[str]:
        """Extract authentication indicators from OpenAPI security definitions."""
        auth_indicators = []
        try:
            security_schemes = openapi_spec.get('components', {}).get('securitySchemes', {})
            if security_schemes:
                auth_indicators.extend(security_schemes.keys())
        except:
            pass
        return auth_indicators

    @staticmethod
    def import_postman(collection: Dict[str, Any]) -> ImportResult:
        """Import Postman collection JSON."""
        endpoints = []
        warnings = []
        errors = []
        
        try:
            # Process Postman collection items
            def process_items(items, folder_name=""):
                local_endpoints = []
                for item in items:
                    if 'item' in item:  # Folder
                        folder_endpoints = process_items(item['item'], item.get('name', folder_name))
                        local_endpoints.extend(folder_endpoints)
                    else:  # Request
                        if 'request' in item:
                            request = item['request']
                            method = request.get('method', 'GET')
                            endpoint = EndpointInventory(
                                endpoint_id=ApiImport._generate_endpoint_id(method, request.get('url', {}).get('raw', ''), 'postman'),
                                source_type='postman',
                                source_id='postman_import',
                                method=method,
                                path=request.get('url', {}).get('raw', ''),
                                auth_indicators=ApiImport._extract_postman_auth_indicators(request)
                            )
                            local_endpoints.append(endpoint)
                return local_endpoints
            
            # Process top-level items
            items = collection.get('item', [])
            endpoints = process_items(items)
            
            return ImportResult(
                import_id=ApiImport._generate_endpoint_id('postman', str(len(collection)), 'postman'),
                source_type='postman',
                source_name=collection.get('info', {}).get('name'),
                created_at_utc="2026-01-01T00:00:00Z",
                endpoint_count=len(endpoints),
                endpoints=endpoints,
                warnings=warnings,
                errors=errors
            )
        except Exception as e:
            errors.append(f"Failed to parse Postman collection: {str(e)}")
            return ImportResult(
                import_id="",
                source_type='postman',
                source_name=None,
                created_at_utc="",
                endpoint_count=0,
                endpoints=[],
                warnings=[],
                errors=[f"Failed to parse Postman collection: {str(e)}"]
            )
    
    @staticmethod
    def _extract_postman_auth_indicators(request) -> List[str]:
        """Extract authentication indicators from Postman request."""
        auth_indicators = []
        if 'auth' in request:
            auth_indicators.append(request['auth'].get('type', 'unknown'))
        return auth_indicators

    @staticmethod
    def import_har(har_data: Dict[str, Any]) -> ImportResult:
        """Import HAR file data."""
        endpoints = []
        warnings = []
        errors = []
        
        try:
            entries = har_data.get('log', {}).get('entries', [])
            for entry in entries:
                if 'request' in entry:
                    req = entry['request']
                    method = req.get('method', 'GET')
                    url = req.get('url', '')
                    
                    endpoint = EndpointInventory(
                        endpoint_id=ApiImport._generate_endpoint_id(method, url, 'har'),
                        source_type='har',
                        source_id='har_import',
                        method=method,
                        path=url,
                        host=ApiImport._extract_host_from_url(url),
                        scheme=ApiImport._extract_scheme_from_url(url)
                    )
                    endpoints.append(endpoint)
            
            return ImportResult(
                import_id=ApiImport._generate_endpoint_id('har', str(len(har_data)), 'har'),
                source_type='har',
                source_name='HAR Import',
                created_at_utc="2026-01-01T00:00:00Z",
                endpoint_count=len(endpoints),
                endpoints=endpoints,
                warnings=warnings,
                errors=errors
            )
        except Exception as e:
            errors.append(f"Failed to parse HAR data: {str(e)}")
            return ImportResult(
                import_id="",
                source_type='har',
                source_name=None,
                created_at_utc="",
                endpoint_count=0,
                endpoints=[],
                warnings=[],
                errors=[f"Failed to parse HAR data: {str(e)}"]
            )
    
    @staticmethod
    def _extract_host_from_url(url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except:
            return ""
    
    @staticmethod
    def _extract_scheme_from_url(url: str) -> str:
        """Extract scheme from URL."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.scheme or ""
        except:
            return ""

    @staticmethod
    def create_evidence(import_result: ImportResult) -> EvidenceRecord:
        """Create evidence record from import result."""
        return EvidenceRecord(
            evidence_type=EvidenceType.ADAPTER_OUTPUT,
            source_type=EvidenceSourceType.UNKNOWN,
            source_id=import_result.source_type,
            target=None,
            normalized_target=None,
            title=f"API Import Evidence - {import_result.source_type}",
            summary=f"Imported {import_result.endpoint_count} endpoints from {import_result.source_type}",
            structured_data={
                "endpoint_count": import_result.endpoint_count,
                "source_type": import_result.source_type,
                "import_id": import_result.import_id
            },
            confidence="medium",
            redaction_applied=False
        )
