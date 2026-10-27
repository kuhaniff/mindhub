"""Unit tests for mindhub_oauth.metadata and discovery routes."""
from __future__ import annotations

import unittest

from mindhub_oauth.config import Config
from mindhub_oauth.metadata import (
    build_protected_resource_metadata,
    build_authorization_server_metadata,
)


def sample_config() -> Config:
    return Config.from_env(
        {
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "MINDHUB_UPSTREAM_API_KEY": "test-key",
            "FACADE_OWNER_PASSWORD_HASH": "scrypt$32768$8$1$c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=$aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
            "FACADE_DB_PATH": "/tmp/test_meta.db",
        }
    )


class TestOAuthMetadata(unittest.TestCase):
    def test_protected_resource_metadata_exact_shape(self) -> None:
        cfg = sample_config()
        prm = build_protected_resource_metadata(cfg)

        self.assertEqual(prm["resource"], "https://mindhub.example.com/mcp")
        self.assertEqual(prm["authorization_servers"], ["https://mindhub.example.com"])
        self.assertEqual(
            prm["scopes_supported"], ["mindhub:read", "mindhub:write"]
        )
        self.assertEqual(prm["bearer_methods_supported"], ["header"])

        # Resource must not have a trailing slash
        self.assertFalse(prm["resource"].endswith("/"))
        # Exactly one authorization server
        self.assertEqual(len(prm["authorization_servers"]), 1)

    def test_authorization_server_metadata_exact_shape(self) -> None:
        cfg = sample_config()
        asm = build_authorization_server_metadata(cfg)

        self.assertEqual(asm["issuer"], "https://mindhub.example.com")
        self.assertEqual(
            asm["authorization_endpoint"], "https://mindhub.example.com/authorize"
        )
        self.assertEqual(asm["token_endpoint"], "https://mindhub.example.com/token")
        self.assertEqual(
            asm["registration_endpoint"], "https://mindhub.example.com/register"
        )
        self.assertEqual(
            asm["revocation_endpoint"], "https://mindhub.example.com/revoke"
        )
        self.assertEqual(asm["response_types_supported"], ["code"])
        self.assertEqual(
            asm["grant_types_supported"], ["authorization_code", "refresh_token"]
        )
        self.assertEqual(asm["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(
            asm["token_endpoint_auth_methods_supported"],
            ["none", "client_secret_post"],
        )
        self.assertEqual(
            asm["scopes_supported"],
            ["mindhub:read", "mindhub:write", "offline_access"],
        )
        self.assertTrue(asm["authorization_response_iss_parameter_supported"])

        # Must NOT advertise CIMD
        self.assertNotIn("client_id_metadata_document_supported", asm)


if __name__ == "__main__":
    unittest.main()
