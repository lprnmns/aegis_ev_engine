from __future__ import annotations

from typing import Any, Dict
import json

from .imports.api_import import ApiImport


def import_openapi_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle import-openapi command."""
    try:
        # Get the OpenAPI spec from payload
        openapi_spec = payload.get("data", {})
        
        # Import the OpenAPI spec
        result = ApiImport.import_openapi(openapi_spec)
        
        return {
            "ok": True,
            "command": "import-openapi",
            "result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "warnings": result.warnings,
                "errors": result.errors
            },
            "error": None
        }
    except Exception as e:
        return {
            "ok": False,
            "command": "import-openapi",
            "result": None,
            "error": {
                "code": "import_failed",
                "message": str(e)
            }
        }


def import_postman_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle import-postman command."""
    try:
        # Get the Postman collection from payload
        postman_collection = payload.get("data", {})
        
        # Import the Postman collection
        result = ApiImport.import_postman(postman_collection)
        
        return {
            "ok": True,
            "command": "import-postman",
            "result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "warnings": result.warnings,
                "errors": result.errors
            },
            "error": None
        }
    except Exception as e:
        return {
            "ok": False,
            "command": "import-postman",
            "result": None,
            "error": {
                "code": "import_failed",
                "message": str(e)
            }
        }


def import_har_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle import-har command."""
    try:
        # Get the HAR data from payload
        har_data = payload.get("data", {})
        
        # Import the HAR data
        result = ApiImport.import_har(har_data)
        
        return {
            "ok": True,
            "command": "import-har",
            "result": {
                "import_id": result.import_id,
                "source_type": result.source_type,
                "endpoint_count": result.endpoint_count,
                "warnings": result.warnings,
                "errors": result.errors
            },
            "error": None
        }
    except Exception as e:
        return {
            "ok": False,
            "command": "import-har",
            "result": None,
            "error": {
                "code": "import_failed",
                "message": str(e)
            }
        }
