import unittest
from datetime import datetime

from aegis_ev.imports.api_import import (
    EndpointInventory,
    ImportResult,
    ApiImport,
)


class TestApiImportFoundation(unittest.TestCase):
    """Test cases for API import foundation functionality."""

    def test_endpoint_inventory_creation(self):
        """Test that EndpointInventory objects can be created properly."""
        endpoint = EndpointInventory(
            endpoint_id="test123",
            source_type="openapi",
            source_id="test_source",
            method="GET",
            path="/test"
        )
        
        self.assertEqual(endpoint.endpoint_id, "test123")
        self.assertEqual(endpoint.source_type, "openapi")
        self.assertEqual(endpoint.method, "GET")
        self.assertEqual(endpoint.path, "/test")

    def test_import_result_creation(self):
        """Test that ImportResult objects can be created properly."""
        result = ImportResult(
            import_id="import123",
            source_type="openapi",
            source_name="Test API",
            created_at_utc=datetime.now().isoformat(),
            endpoint_count=1,
            endpoints=[],
            warnings=[],
            errors=[]
        )
        
        self.assertEqual(result.import_id, "import123")
        self.assertEqual(result.source_type, "openapi")
        self.assertEqual(result.source_name, "Test API")
        self.assertEqual(result.endpoint_count, 1)

    def test_openapi_import(self):
        """Test OpenAPI import functionality."""
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "description": "Retrieve list of users",
                        "tags": ["users"]
                    }
                }
            }
        }
        
        result = ApiImport.import_openapi(openapi_spec)
        
        self.assertEqual(result.source_type, "openapi")
        self.assertGreaterEqual(len(result.endpoints), 0)
        self.assertEqual(result.errors, [])

    def test_postman_import(self):
        """Test Postman collection import functionality."""
        collection = {
            "info": {
                "name": "Test Collection"
            },
            "item": [
                {
                    "name": "Get Users",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "https://api.example.com/users"
                        }
                    }
                }
            ]
        }
        
        result = ApiImport.import_postman(collection)
        
        self.assertEqual(result.source_type, "postman")
        self.assertEqual(result.source_name, "Test Collection")
        self.assertEqual(result.errors, [])

    def test_har_import(self):
        """Test HAR import functionality."""
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/users"
                        }
                    }
                ]
            }
        }
        
        result = ApiImport.import_har(har_data)
        
        self.assertEqual(result.source_type, "har")
        self.assertEqual(result.source_name, "HAR Import")
        self.assertEqual(result.errors, [])

    def test_endpoint_id_generation(self):
        """Test deterministic endpoint ID generation."""
        endpoint_id = ApiImport._generate_endpoint_id("GET", "/users", "openapi")
        self.assertIsInstance(endpoint_id, str)
        self.assertEqual(len(endpoint_id), 16)

if __name__ == "__main__":
    unittest.main()
