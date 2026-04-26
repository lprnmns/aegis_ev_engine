from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
from aegis_ev.adapters.framework import SafeToolAdapter, AdapterMetadata, ToolActionRequest
from aegis_ev.models import ImpactLevel
from aegis_ev.imports.api_import import ApiImport


@dataclass
class ApiImportAdapter(SafeToolAdapter):
    """Safe adapter for API import operations."""
    
    metadata = AdapterMetadata(
        adapter_id="api_import",
        display_name="API Import Adapter",
        description="Imports OpenAPI/Postman/HAR files for endpoint discovery",
        supported_actions=("import_openapi", "import_postman", "import_har"),
        default_impact_level=ImpactLevel.GREEN,
        requires_network=False,
        requires_authentication=False,
        allowed_target_types=("file", "url"),
        allowed_argument_schema={
            "data": "object",
            "file_path": "str"
        },
        timeout_seconds=30,
        max_requests=1,
        max_concurrency=1,
        produces_evidence=True,
        safe_mode_supported=True,
    )

    def import_openapi(self, openapi_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import OpenAPI specification."""
        result = ApiImport.import_openapi(openapi_data)
        return {
            "import_result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "endpoints": [ep.__dict__ for ep in result.endpoints]
            }
        }

    def import_postman(self, postman_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import Postman collection."""
        result = ApiImport.import_postman(postman_data)
        return {
            "import_result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "endpoints": [ep.__dict__ for ep in result.endpoints]
            }
        }

    def import_har(self, har_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import HAR file."""
        result = ApiImport.import_har(har_data)
        return {
            "import_result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "endpoints": [ep.__dict__ for ep in result.endpoints]
            }
        }
