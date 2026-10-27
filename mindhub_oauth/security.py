"""Security utilities: PKCE, password hashing, redirect URI validation, rate limiting."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import threading
import time
import urllib.parse
from typing import Callable, Mapping, Sequence

from starlette.requests import Request

logger = logging.getLogger(__name__)

VERIFIER_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
CODE_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
ALLOWED_CLAUDE_REDIRECTS = frozenset(
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
    ]
)
ALLOWED_GOOGLE_HOSTS = frozenset(
    [
        "oauth-redirect.googleusercontent.com",
        "oauth-redirect-sandbox.googleusercontent.com",
    ]
)


def is_loopback_ip(ip_str: str) -> bool:
    """Return True if ip_str is a valid IPv4/IPv6 loopback address."""
    if not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False


def validate_code_challenge(challenge: str) -> bool:
    """Validate that code_challenge is exactly 43 base64url characters without padding."""
    if not isinstance(challenge, str):
        return False
    return bool(CODE_CHALLENGE_PATTERN.match(challenge))


def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(s: str) -> bytes:
    """Base64url decode with optional padding."""
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def generate_secret(nbytes: int = 32) -> str:
    """Generate cryptographically secure random token (>= 256 bits)."""
    return secrets.token_urlsafe(nbytes)


# ---------------------------------------------------------------------------
# PKCE (RFC 7636)
# ---------------------------------------------------------------------------


def compute_code_challenge(verifier: str, method: str = "S256") -> str:
    """Compute PKCE code challenge. Only S256 is supported."""
    if method != "S256":
        raise ValueError(f"Unsupported PKCE code_challenge_method: {method}. Only S256 is supported.")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64url_encode(digest)


def validate_code_verifier(verifier: str) -> bool:
    """Validate RFC 7636 code verifier syntax: 43-128 unreserved characters."""
    if not isinstance(verifier, str):
        return False
    if not (43 <= len(verifier) <= 128):
        return False
    return set(verifier).issubset(VERIFIER_CHARS)


def verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Verify PKCE verifier against challenge in constant time."""
    if not validate_code_verifier(verifier):
        return False
    if method != "S256":
        return False
    try:
        computed = compute_code_challenge(verifier, method="S256")
        return hmac.compare_digest(computed, challenge)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Password hashing (scrypt)
# ---------------------------------------------------------------------------

SCRYPT_MAXMEM: int = 64 * 1024 * 1024  # 64 MiB


def hash_password(password: str, n: int = 32768, r: int = 8, p: int = 1) -> str:
    """Hash password using scrypt with explicitly bounded memory."""
    salt = secrets.token_bytes(32)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        maxmem=SCRYPT_MAXMEM,
        dklen=32,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"scrypt${n}${r}${p}${salt_b64}${key_b64}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against scrypt hash in constant time without timing leakage."""
    dummy_salt = b"\x00" * 32

    parts = password_hash.split("$") if isinstance(password_hash, str) else []
    is_valid_format = len(parts) == 6 and parts[0] == "scrypt"

    try:
        if is_valid_format:
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])
            salt = base64.b64decode(parts[4])
            expected_key = base64.b64decode(parts[5])
        else:
            n, r, p = 32768, 8, 1
            salt = dummy_salt
            expected_key = b"\x00" * 32
    except (ValueError, TypeError, base64.binascii.Error):
        is_valid_format = False
        n, r, p = 32768, 8, 1
        salt = dummy_salt
        expected_key = b"\x00" * 32

    # Always perform the scrypt work
    pw_bytes = password.encode("utf-8") if isinstance(password, str) else b""
    try:
        derived_key = hashlib.scrypt(
            pw_bytes,
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=SCRYPT_MAXMEM,
            dklen=len(expected_key) if expected_key else 32,
        )
    except ValueError as exc:
        if is_valid_format:
            logger.error("scrypt calculation failed: %s", exc)
            return False
        derived_key = b"\x01" * 32
    except TypeError:
        derived_key = b"\x01" * 32

    matches = hmac.compare_digest(derived_key, expected_key)
    return is_valid_format and matches and bool(password)


# ---------------------------------------------------------------------------
# Redirect URI validation
# ---------------------------------------------------------------------------


def validate_redirect_uri(uri: str, extra_allowed: Sequence[str] = ()) -> bool:
    """Strictly validate redirect URI against allowlist and relay rules."""
    try:
        if not isinstance(uri, str) or not uri:
            return False

        # Check for whitespace, control characters, or invalid character sequences
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in uri):
            return False

        # Fast path: exact matches in Claude allowlist or extra allowlist
        if uri in ALLOWED_CLAUDE_REDIRECTS or uri in extra_allowed:
            return True

        try:
            parsed = urllib.parse.urlsplit(uri)
        except Exception:
            return False

        # Must be HTTPS
        if parsed.scheme.lower() != "https":
            return False

        # Disallow userinfo, port, query, fragment
        if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
            return False

        # Disallow path traversal
        if ".." in parsed.path or "%2e" in parsed.path.lower():
            return False

        host = (parsed.hostname or "").lower()

        # Google relay validation
        if host in ALLOWED_GOOGLE_HOSTS:
            # Path must start with /r/ or /a/ with at least one path segment after
            if re.match(r"^/(r|a)/[A-Za-z0-9_-]+", parsed.path):
                return True
            return False

        return False
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe fixed-window rate limiter with memory bounding."""

    def __init__(self, max_requests: int, window_seconds: int = 60, max_keys: int = 10000) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._lock = threading.RLock()
        self._hits: dict[str, list[float]] = {}

    def prune(self, now: float | None = None) -> None:
        """Prune keys whose histories have expired."""
        now_ts = now if now is not None else time.time()
        window_start = now_ts - self.window_seconds
        with self._lock:
            empty_keys = [k for k, v in self._hits.items() if not any(t > window_start for t in v)]
            for k in empty_keys:
                self._hits.pop(k, None)

    def check(self, key: str, now_fn: Callable[[], float] | None = None) -> bool:
        """Record attempt and return True if allowed, False if rate limited."""
        now = now_fn() if now_fn else time.time()
        window_start = now - self.window_seconds

        with self._lock:
            history = self._hits.get(key, [])
            valid = [t for t in history if t > window_start]
            if len(valid) >= self.max_requests:
                self._hits[key] = valid
                return False

            valid.append(now)
            if key not in self._hits:
                if len(self._hits) >= self.max_keys:
                    empty_keys = [k for k, v in self._hits.items() if not any(t > window_start for t in v)]
                    for k in empty_keys:
                        self._hits.pop(k, None)
                    while len(self._hits) >= self.max_keys:
                        self._hits.pop(next(iter(self._hits)), None)

            self._hits[key] = valid
            return True

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


class LockoutTracker:
    """Tracks failed password attempts for IP and global lockout with memory bounding."""

    def __init__(self, max_failures: int, window_seconds: int = 900, max_keys: int = 10000) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._lock = threading.RLock()
        self._failures: dict[str, list[float]] = {}

    def prune(self, now: float | None = None) -> None:
        """Prune keys whose failure history has expired."""
        now_ts = now if now is not None else time.time()
        window_start = now_ts - self.window_seconds
        with self._lock:
            empty_keys = [k for k, v in self._failures.items() if not any(t > window_start for t in v)]
            for k in empty_keys:
                self._failures.pop(k, None)

    def is_locked(self, key: str, now: float) -> bool:
        window_start = now - self.window_seconds
        with self._lock:
            history = self._failures.get(key, [])
            valid = [t for t in history if t > window_start]
            if not valid:
                self._failures.pop(key, None)
                return False
            self._failures[key] = valid
            return len(valid) >= self.max_failures

    def record_failure(self, key: str, now: float) -> None:
        window_start = now - self.window_seconds
        with self._lock:
            history = self._failures.get(key, [])
            valid = [t for t in history if t > window_start]
            valid.append(now)
            if key not in self._failures:
                if len(self._failures) >= self.max_keys:
                    empty_keys = [k for k, v in self._failures.items() if not any(t > window_start for t in v)]
                    for k in empty_keys:
                        self._failures.pop(k, None)
                    while len(self._failures) >= self.max_keys:
                        self._failures.pop(next(iter(self._failures)), None)
            self._failures[key] = valid

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._failures.clear()
            else:
                self._failures.pop(key, None)


def extract_client_ip(request: Request, trust_cf_headers: bool = True) -> str:
    """Extract client IP, trusting CF-Connecting-IP only if TCP peer is loopback."""
    peer_host = request.client.host if request.client else "unknown"

    if trust_cf_headers and is_loopback_ip(peer_host):
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            cf_ip = cf_ip.strip()
            try:
                ipaddress.ip_address(cf_ip)
                return cf_ip
            except ValueError:
                pass

    return peer_host
