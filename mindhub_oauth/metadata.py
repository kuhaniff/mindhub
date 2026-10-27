"""OAuth Protected Resource and Authorization Server metadata builders."""
from __future__ import annotations

from typing import Any

from .config import Config


def build_protected_resource_metadata(config: Config) -> dict[str, Any]:
    """Build Protected Resource Metadata (PRM) document (RFC 8414 / MCP OAuth spec)."""
    return {
        "resource": config.resource,
        "authorization_servers": [config.issuer],
        "scopes_supported": ["mindhub:read", "mindhub:write"],
        "bearer_methods_supported": ["header"],
    }


def build_authorization_server_metadata(config: Config) -> dict[str, Any]:
    """Build OAuth 2.1 Authorization Server Metadata document (RFC 8414)."""
    return {
        "issuer": config.issuer,
        "authorization_endpoint": f"{config.issuer}/authorize",
        "token_endpoint": f"{config.issuer}/token",
        "registration_endpoint": f"{config.issuer}/register",
        "revocation_endpoint": f"{config.issuer}/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mindhub:read", "mindhub:write", "offline_access"],
        "authorization_response_iss_parameter_supported": True,
    }
