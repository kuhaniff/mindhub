"""Configuration parsing and fail-closed validation for Mindhub OAuth facade."""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import urllib.parse
from dataclasses import dataclass
from typing import Mapping, Sequence

from .security import SCRYPT_MAXMEM

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset(["127.0.0.1", "localhost", "::1"])
ALLOWED_SCOPES = frozenset(["mindhub:read", "mindhub:write", "offline_access"])


class ConfigError(ValueError):
    """Raised when configuration validation fails."""


def is_loopback_host(host: str, allow_insecure_local: bool = False) -> bool:
    """Return True if host is localhost, a loopback IP literal, or testserver (if allowed)."""
    if not isinstance(host, str):
        return False
    h = host.strip().lower()
    if allow_insecure_local and h == "testserver":
        return True
    if h == "localhost":
        return True
    try:
        ip_str = h.strip("[]")
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return False


def _parse_bool(val: str | None, default: bool) -> bool:
    if val is None:
        return default
    v = val.strip().lower()
    return v in ("1", "true", "yes", "on")


def _parse_scopes(val: str | None, default: str) -> frozenset[str]:
    raw = val if val is not None else default
    # Split on whitespace or commas
    parts = [s.strip() for item in raw.split(",") for s in item.split()]
    return frozenset(p for p in parts if p)


def _validate_password_hash(hash_val: str) -> None:
    parts = hash_val.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ConfigError("FACADE_OWNER_PASSWORD_HASH must match format: scrypt$<N>$<r>$<p>$<salt_b64>$<hash_b64>")
    try:
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        if n < 16384 or n > 131072 or (n & (n - 1)) != 0:
            raise ConfigError(f"scrypt N must be a power of 2 between 16384 and 131072 (got {n})")
        if r < 1 or r > 16:
            raise ConfigError(f"scrypt r must be between 1 and 16 (got {r})")
        if p < 1 or p > 4:
            raise ConfigError(f"scrypt p must be between 1 and 4 (got {p})")
        if 128 * r * (n + p + 2) > SCRYPT_MAXMEM:
            raise ConfigError(
                f"scrypt parameters exceed memory limit of {SCRYPT_MAXMEM} bytes "
                f"(requires {128 * r * (n + p + 2)} bytes)"
            )

        def _decode(s: str) -> bytes:
            rem = len(s) % 4
            if rem:
                s += "=" * (4 - rem)
            return base64.b64decode(s.replace("-", "+").replace("_", "/"), validate=True)

        salt = _decode(parts[4])
        if len(salt) < 16:
            raise ConfigError(f"scrypt salt must be at least 16 bytes (got {len(salt)})")

        key = _decode(parts[5])
        if len(key) != 32:
            raise ConfigError(f"scrypt key must be exactly 32 bytes (got {len(key)})")
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(
            "FACADE_OWNER_PASSWORD_HASH parameters or base64 components are invalid"
        ) from exc


@dataclass(frozen=True)
class Config:
    public_url: str
    host: str
    port: int
    upstream_url: str
    upstream_api_key: str
    db_path: str
    owner_password_hash: str
    max_scope: frozenset[str]
    default_scope: frozenset[str]
    access_ttl_seconds: int
    refresh_ttl_seconds: int
    code_ttl_seconds: int
    max_clients: int
    extra_redirect_uris: tuple[str, ...]
    trust_cf_headers: bool
    allow_insecure_local: bool
    google_meta_refresh: bool

    @property
    def issuer(self) -> str:
        return self.public_url

    @property
    def resource(self) -> str:
        return f"{self.public_url}/mcp"

    def __repr__(self) -> str:
        return (
            f"<Config public_url={self.public_url!r} host={self.host!r}:{self.port} "
            f"upstream_url={self.upstream_url!r} db_path={self.db_path!r} "
            f"max_scope={sorted(self.max_scope)!r} default_scope={sorted(self.default_scope)!r} "
            f"secrets=[REDACTED]>"
        )

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Config:
        env = os.environ if environ is None else environ

        # 1. Insecure local override
        allow_insecure_local = _parse_bool(env.get("FACADE_ALLOW_INSECURE_LOCAL"), False)
        if allow_insecure_local:
            logger.warning("FACADE_ALLOW_INSECURE_LOCAL is enabled; insecure local settings permitted")

        # 2. Public URL (required)
        public_url = env.get("FACADE_PUBLIC_URL", "").strip()
        if not public_url:
            raise ConfigError("FACADE_PUBLIC_URL is required")

        parsed_pub = urllib.parse.urlsplit(public_url)
        if allow_insecure_local:
            if parsed_pub.scheme not in ("https", "http"):
                raise ConfigError("FACADE_PUBLIC_URL scheme must be https (or http in insecure local mode)")
        else:
            if parsed_pub.scheme != "https":
                raise ConfigError("FACADE_PUBLIC_URL must use https scheme")

        if not parsed_pub.netloc or parsed_pub.username or parsed_pub.password:
            raise ConfigError("FACADE_PUBLIC_URL must have a valid host without userinfo")

        if parsed_pub.path and parsed_pub.path != "":
            raise ConfigError("FACADE_PUBLIC_URL must not contain a path or trailing slash")

        if parsed_pub.query or parsed_pub.fragment:
            raise ConfigError("FACADE_PUBLIC_URL must not contain query parameters or fragments")

        # 3. Host / Port
        host = env.get("FACADE_HOST", "127.0.0.1").strip()
        allow_non_loopback = _parse_bool(env.get("FACADE_ALLOW_NON_LOOPBACK_BIND"), False)
        if not allow_non_loopback and not is_loopback_host(host, allow_insecure_local=allow_insecure_local):
            raise ConfigError(f"FACADE_HOST must be loopback (got {host}); set FACADE_ALLOW_NON_LOOPBACK_BIND=1 to override")

        try:
            port = int(env.get("FACADE_PORT", "8089"))
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError as exc:
            raise ConfigError("FACADE_PORT must be an integer between 1 and 65535") from exc

        # 4. Upstream URL (SSRF guard)
        upstream_url = env.get("FACADE_UPSTREAM_URL", "http://127.0.0.1:8088/mcp").strip()
        parsed_up = urllib.parse.urlsplit(upstream_url)
        if parsed_up.scheme != "http":
            raise ConfigError("FACADE_UPSTREAM_URL must use http scheme")

        up_host = parsed_up.hostname or ""
        if not is_loopback_host(up_host, allow_insecure_local=allow_insecure_local):
            raise ConfigError(f"FACADE_UPSTREAM_URL host must be loopback (got {up_host})")

        # 5. Upstream API key (required)
        upstream_api_key = env.get("MINDHUB_UPSTREAM_API_KEY", "").strip()
        if not upstream_api_key:
            raise ConfigError("MINDHUB_UPSTREAM_API_KEY is required and must not be empty")

        # 6. DB path
        db_path = env.get("FACADE_DB_PATH", "oauth.db").strip()
        if not db_path:
            raise ConfigError("FACADE_DB_PATH must not be empty")
        if not allow_insecure_local and not os.path.isabs(db_path):
            raise ConfigError(f"FACADE_DB_PATH must be an absolute path (got {db_path!r})")

        # 7. Owner password hash (required)
        owner_password_hash = env.get("FACADE_OWNER_PASSWORD_HASH", "").strip()
        if not owner_password_hash:
            raise ConfigError("FACADE_OWNER_PASSWORD_HASH is required and must not be empty")
        _validate_password_hash(owner_password_hash)

        # 8. Scopes
        max_scope = _parse_scopes(env.get("FACADE_MAX_SCOPE"), "mindhub:read")
        default_scope = _parse_scopes(env.get("FACADE_DEFAULT_SCOPE"), "mindhub:read")

        unknown_max = max_scope - ALLOWED_SCOPES
        if unknown_max:
            raise ConfigError(f"FACADE_MAX_SCOPE contains unknown scopes: {sorted(unknown_max)}")

        unknown_def = default_scope - ALLOWED_SCOPES
        if unknown_def:
            raise ConfigError(f"FACADE_DEFAULT_SCOPE contains unknown scopes: {sorted(unknown_def)}")

        if not default_scope.issubset(max_scope):
            raise ConfigError("FACADE_DEFAULT_SCOPE must be a subset of FACADE_MAX_SCOPE")

        # 9. TTLs
        try:
            access_ttl = int(env.get("FACADE_ACCESS_TTL_SECONDS", "900"))
            if not (1 <= access_ttl <= 3600):
                raise ValueError
        except ValueError as exc:
            raise ConfigError("FACADE_ACCESS_TTL_SECONDS must be an integer between 1 and 3600") from exc

        try:
            refresh_ttl = int(env.get("FACADE_REFRESH_TTL_SECONDS", "2592000"))
            if refresh_ttl < 1:
                raise ValueError
        except ValueError as exc:
            raise ConfigError("FACADE_REFRESH_TTL_SECONDS must be a positive integer") from exc

        try:
            code_ttl = int(env.get("FACADE_CODE_TTL_SECONDS", "60"))
            if not (1 <= code_ttl <= 120):
                raise ValueError
        except ValueError as exc:
            raise ConfigError("FACADE_CODE_TTL_SECONDS must be an integer between 1 and 120") from exc

        try:
            max_clients = int(env.get("FACADE_MAX_CLIENTS", "50"))
            if max_clients < 1:
                raise ValueError
        except ValueError as exc:
            raise ConfigError("FACADE_MAX_CLIENTS must be a positive integer") from exc

        # 10. Extra redirect URIs
        extra_redirect_raw = env.get("FACADE_EXTRA_REDIRECT_URIS", "").strip()
        extra_redirects: list[str] = []
        if extra_redirect_raw:
            for item in extra_redirect_raw.split(","):
                item = item.strip()
                if item:
                    parsed_item = urllib.parse.urlsplit(item)
                    if parsed_item.scheme != "https":
                        raise ConfigError(f"Extra redirect URI must use https scheme: {item}")
                    if parsed_item.fragment:
                        raise ConfigError(f"Extra redirect URI must not contain fragment: {item}")
                    extra_redirects.append(item)

        trust_cf = _parse_bool(env.get("FACADE_TRUST_CF_HEADERS"), True)
        google_meta_refresh = _parse_bool(env.get("FACADE_GOOGLE_META_REFRESH"), True)

        return cls(
            public_url=public_url,
            host=host,
            port=port,
            upstream_url=upstream_url,
            upstream_api_key=upstream_api_key,
            db_path=db_path,
            owner_password_hash=owner_password_hash,
            max_scope=max_scope,
            default_scope=default_scope,
            access_ttl_seconds=access_ttl,
            refresh_ttl_seconds=refresh_ttl,
            code_ttl_seconds=code_ttl,
            max_clients=max_clients,
            extra_redirect_uris=tuple(extra_redirects),
            trust_cf_headers=trust_cf,
            allow_insecure_local=allow_insecure_local,
            google_meta_refresh=google_meta_refresh,
        )
