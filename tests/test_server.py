"""Unit tests for standalone Mindhub server.py."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

try:
    from starlette.testclient import TestClient
    from mindhub.server import create_app
    _SERVER_AVAILABLE = True
except ImportError:
    _SERVER_AVAILABLE = False

from mindhub.memory import InMemoryMemoryPersistence
from mindhub.project_state import InMemoryProjectStatePersistence


@unittest.skipUnless(_SERVER_AVAILABLE, "fastapi and mcp packages required for server tests")
class TestServerHealthAndAuth(unittest.TestCase):
    def setUp(self) -> None:
        self.mem = InMemoryMemoryPersistence()
        self.state = InMemoryProjectStatePersistence()
        self.app = create_app(memory_backend=self.mem, state_backend=self.state)
        self.client = TestClient(self.app)

    def test_health_endpoint_returns_200(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "mindhub"})

    def test_unconfigured_keys_returns_401(self) -> None:
        with patch.dict(os.environ, {"MINDHUB_API_KEYS": ""}, clear=False):
            response = self.client.get("/mcp")
            self.assertEqual(response.status_code, 401)
            self.assertIn("not configured", response.json().get("detail", ""))

    def test_missing_api_key_header_returns_401(self) -> None:
        with patch.dict(os.environ, {"MINDHUB_API_KEYS": "valid-key-1,valid-key-2"}):
            response = self.client.get("/mcp")
            self.assertEqual(response.status_code, 401)
            self.assertIn("invalid or missing", response.json().get("detail", ""))

    def test_invalid_api_key_header_returns_401(self) -> None:
        with patch.dict(os.environ, {"MINDHUB_API_KEYS": "valid-key-1,valid-key-2"}):
            response = self.client.get("/mcp", headers={"X-API-Key": "bad-key"})
            self.assertEqual(response.status_code, 401)
            self.assertIn("invalid or missing", response.json().get("detail", ""))

    def test_valid_api_key_passes_auth(self) -> None:
        with patch.dict(os.environ, {"MINDHUB_API_KEYS": "valid-key-1,valid-key-2"}):
            response = self.client.get("/mcp", headers={"X-API-Key": "valid-key-1"})
            self.assertNotEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
