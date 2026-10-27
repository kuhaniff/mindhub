"""OAuth protocol endpoints: metadata, registration, authorize, token, revoke, health."""
from __future__ import annotations

import asyncio
import base64
import html
import hmac
import json
import urllib.parse
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .config import Config
from .consent import (
    SECURITY_HEADERS,
    render_consent_page,
    render_html_error,
    render_meta_refresh_response,
)
from .metadata import (
    build_authorization_server_metadata,
    build_protected_resource_metadata,
)
from .security import (
    LockoutTracker,
    RateLimiter,
    compute_code_challenge,
    extract_client_ip,
    generate_secret,
    validate_code_challenge,
    validate_code_verifier,
    validate_redirect_uri,
    verify_password,
    verify_pkce,
)
from .store import OAuthStore

ALLOWED_SCOPES = frozenset(["mindhub:read", "mindhub:write", "offline_access"])
MAX_STATE_LENGTH = 4096


def _html_error(status_code: int, title: str, description: str) -> HTMLResponse:
    return render_html_error(status_code, title, description)


def _redirect_error(
    redirect_uri: str,
    error: str,
    error_description: str,
    state: str | None,
    iss: str,
) -> RedirectResponse:
    params: dict[str, str] = {
        "error": error,
        "error_description": error_description,
        "iss": iss,
    }
    if state is not None:
        params["state"] = state

    sep = "&" if "?" in redirect_uri else "?"
    target = f"{redirect_uri}{sep}{urllib.parse.urlencode(params)}"
    return RedirectResponse(target, status_code=302, headers={"Cache-Control": "no-store"})


class PayloadTooLargeError(Exception):
    """Raised when request body exceeds maximum allowed size."""


class InvalidContentLengthError(Exception):
    """Raised when Content-Length header is invalid."""


class FormParseError(Exception):
    """Raised when form/query parsing fails due to field limits or duplicates."""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


async def read_capped_body(request: Request, limit: int) -> bytes:
    """Read request body up to limit bytes, raising PayloadTooLargeError as soon as limit is exceeded."""
    cl_hdr = request.headers.get("content-length")
    if cl_hdr is not None:
        try:
            cl = int(cl_hdr)
            if cl > limit:
                raise PayloadTooLargeError(f"Content-Length exceeds limit ({limit} bytes)")
        except ValueError as exc:
            raise InvalidContentLengthError("Invalid Content-Length header") from exc

    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise PayloadTooLargeError(f"Body size exceeds limit ({limit} bytes)")
        chunks.append(chunk)
    return b"".join(chunks)


def _sanitize_param_name(name: str) -> str:
    return "".join(c if (32 <= ord(c) <= 126) else "?" for c in name[:64])


def parse_form_urlencoded(body_bytes: bytes, configured_resource: str) -> dict[str, str]:
    text = body_bytes.decode("utf-8", errors="replace")
    try:
        pairs = urllib.parse.parse_qsl(
            text,
            keep_blank_values=True,
            max_num_fields=50,
            strict_parsing=False,
        )
    except ValueError as exc:
        raise FormParseError("invalid_request", "Too many form fields") from exc

    seen: set[str] = set()
    resources: list[str] = []
    data: dict[str, str] = {}

    for k, v in pairs:
        if k == "resource":
            resources.append(v)
            data[k] = v
            continue
        if k in seen:
            safe_k = _sanitize_param_name(k)
            raise FormParseError("invalid_request", f"Duplicate parameter: {safe_k}")
        seen.add(k)
        data[k] = v

    if resources:
        if len(resources) > 1 and any(r != configured_resource for r in resources):
            raise FormParseError("invalid_request", "Repeated resource parameter with mismatched value")
        data["resource"] = resources[0]

    return data


def parse_query_params(query_string: str, configured_resource: str) -> dict[str, str]:
    try:
        pairs = urllib.parse.parse_qsl(
            query_string,
            keep_blank_values=True,
            max_num_fields=50,
            strict_parsing=False,
        )
    except ValueError as exc:
        raise FormParseError("invalid_request", "Too many query parameters") from exc

    seen: set[str] = set()
    resources: list[str] = []
    data: dict[str, str] = {}

    for k, v in pairs:
        if k == "resource":
            resources.append(v)
            data[k] = v
            continue
        if k in seen:
            safe_k = _sanitize_param_name(k)
            raise FormParseError("invalid_request", f"Duplicate query parameter: {safe_k}")
        seen.add(k)
        data[k] = v

    if resources:
        if len(resources) > 1 and any(r != configured_resource for r in resources):
            raise FormParseError("invalid_request", "Repeated resource parameter with mismatched value")
        data["resource"] = resources[0]

    return data


class OAuthRoutes:
    """OAuth protocol endpoints handler."""

    def __init__(self, config: Config, store: OAuthStore) -> None:
        self.config = config
        self.store = store
        self.authorize_limiter = RateLimiter(max_requests=30, window_seconds=60)
        self.register_limiter = RateLimiter(max_requests=10, window_seconds=60)
        self.token_limiter = RateLimiter(max_requests=60, window_seconds=60)
        self.ip_lockout = LockoutTracker(max_failures=5, window_seconds=900)
        self.global_lockout = LockoutTracker(max_failures=20, window_seconds=900)

    # -----------------------------------------------------------------------
    # Health & Discovery
    # -----------------------------------------------------------------------

    async def health(self, request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "mindhub-oauth"})

    async def protected_resource_metadata(self, request: Request) -> JSONResponse:
        data = build_protected_resource_metadata(self.config)
        return JSONResponse(data, headers={"Cache-Control": "public, max-age=300"})

    async def authorization_server_metadata(self, request: Request) -> JSONResponse:
        data = build_authorization_server_metadata(self.config)
        return JSONResponse(data, headers={"Cache-Control": "public, max-age=300"})

    # -----------------------------------------------------------------------
    # DCR (RFC 7591)
    # -----------------------------------------------------------------------

    async def register(self, request: Request) -> Response:
        ip = extract_client_ip(request, self.config.trust_cf_headers)
        if not self.register_limiter.check(ip, now_fn=lambda: self.store.now):
            return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Cache-Control": "no-store"})

        if self.store.count_active_clients() >= self.config.max_clients:
            return JSONResponse({"error": "too_many_clients"}, status_code=429, headers={"Cache-Control": "no-store"})

        content_type = request.headers.get("content-type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type != "application/json":
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Content-Type must be application/json"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        try:
            body_bytes = await read_capped_body(request, 8192)
        except PayloadTooLargeError:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Request body exceeds maximum size (8 KiB)"},
                status_code=413,
                headers={"Cache-Control": "no-store"},
            )
        except InvalidContentLengthError:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Invalid Content-Length header"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except Exception:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "JSON object required"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        # Validate redirect_uris (1 to 6)
        redirect_uris = payload.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not (1 <= len(redirect_uris) <= 6):
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": "redirect_uris must be a list of 1 to 6 strings"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        for uri in redirect_uris:
            if not isinstance(uri, str) or not validate_redirect_uri(uri, self.config.extra_redirect_uris):
                # Audit rejection with host only
                host_only = "unknown"
                try:
                    host_only = urllib.parse.urlsplit(uri).hostname or "unknown"
                except Exception:
                    pass
                self.store.log_audit("register_rejected", client_id=None, detail=f"invalid_redirect:{host_only}")
                return JSONResponse(
                    {"error": "invalid_redirect_uri", "error_description": "A supplied redirect_uri is not allowlisted"},
                    status_code=400,
                    headers={"Cache-Control": "no-store"},
                )

        # Validate token_endpoint_auth_method (must be str)
        auth_method = payload.get("token_endpoint_auth_method", "none")
        if not isinstance(auth_method, str) or auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Unsupported token_endpoint_auth_method"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        # Validate grant_types (must be list of str)
        grant_types = payload.get("grant_types", ["authorization_code", "refresh_token"])
        if (
            not isinstance(grant_types, list)
            or not all(isinstance(gt, str) for gt in grant_types)
            or not set(grant_types).issubset({"authorization_code", "refresh_token"})
        ):
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Invalid grant_types"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        # Validate response_types
        response_types = payload.get("response_types", ["code"])
        if response_types != ["code"]:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "response_types must be ['code']"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        # Validate and sanitize client_name
        if "client_name" in payload:
            raw_name = payload["client_name"]
            if raw_name is not None and not isinstance(raw_name, str):
                return JSONResponse(
                    {"error": "invalid_client_metadata", "error_description": "client_name must be a string"},
                    status_code=400,
                    headers={"Cache-Control": "no-store"},
                )
            if raw_name:
                cleaned = "".join(c for c in raw_name if ord(c) >= 32 and ord(c) != 127).strip()[:100]
                client_name = cleaned if cleaned else None
            else:
                client_name = None
        else:
            client_name = None

        client_id = generate_secret(24)
        client_rec = self.store.create_client(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
        )
        self.store.log_audit("register_ok", client_id=client_id, detail=f"name={client_name}")

        resp_data = {
            "client_id": client_rec.client_id,
            "client_id_issued_at": int(client_rec.created_at),
            "client_name": client_rec.client_name,
            "redirect_uris": list(client_rec.redirect_uris),
            "grant_types": list(client_rec.grant_types),
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        return JSONResponse(resp_data, status_code=201, headers={"Cache-Control": "no-store"})

    # -----------------------------------------------------------------------
    # Authorize (GET /authorize)
    # -----------------------------------------------------------------------

    async def authorize(self, request: Request) -> Response:
        query_string = request.scope.get("query_string", b"").decode("utf-8", errors="replace")
        try:
            params = parse_query_params(query_string, self.config.resource)
        except FormParseError as exc:
            return _html_error(400, "Invalid Request", exc.description)

        raw_client_id = params.get("client_id", "")
        client_id = raw_client_id[:64]
        redirect_uri = params.get("redirect_uri", "")
        response_type = params.get("response_type", "")
        state = params.get("state")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "")
        scope = params.get("scope", "")
        resource = params.get("resource")

        # Rate limit per IP
        client_ip = extract_client_ip(request, self.config.trust_cf_headers)
        if not self.authorize_limiter.check(client_ip, now_fn=lambda: self.store.now):
            self.store.log_audit("authorize_rejected", client_id=client_id or None, detail="reason=rate_limited")
            return _html_error(429, "Too Many Requests", "Rate limit exceeded. Please try again later.")

        # Step 1: Validate client and redirect_uri
        client = self.store.get_client(client_id)
        if client is None:
            self.store.log_audit("authorize_rejected", client_id=client_id or None, detail="reason=unknown_client")
            return _html_error(400, "Invalid client", "The requested client_id is invalid, revoked, or unknown.")

        if redirect_uri not in client.redirect_uris:
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=invalid_redirect_uri")
            return _html_error(400, "Invalid redirect URI", "The redirect_uri is not registered for this client.")

        # From here onwards, errors are returned by redirecting to the validated redirect_uri
        iss = self.config.issuer

        # Cap state parameter at MAX_STATE_LENGTH chars
        if state is not None and len(state) > MAX_STATE_LENGTH:
            self.store.log_audit(
                "authorize_rejected",
                client_id=client_id,
                detail=f"reason=state_too_long len={len(state)}",
            )
            return _redirect_error(
                redirect_uri,
                "invalid_request",
                f"state parameter exceeds maximum length of {MAX_STATE_LENGTH} characters",
                state,
                iss,
            )

        # Step 2: Validate response_type
        if response_type != "code":
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=unsupported_response_type")
            return _redirect_error(
                redirect_uri,
                "unsupported_response_type",
                "Only response_type=code is supported",
                state,
                iss,
            )

        # Step 3: Validate PKCE
        if (
            not code_challenge
            or code_challenge_method != "S256"
            or not validate_code_challenge(code_challenge)
        ):
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=invalid_pkce")
            return _redirect_error(
                redirect_uri,
                "invalid_request",
                "PKCE S256 code_challenge of 43 characters (base64url) is required",
                state,
                iss,
            )

        # Step 4: Validate resource
        if resource is not None and resource != self.config.resource:
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=invalid_target_resource")
            return _redirect_error(
                redirect_uri,
                "invalid_target",
                "The requested resource does not match this server's resource identifier",
                state,
                iss,
            )

        # Step 5: Scope calculation
        requested_scopes = [s for s in scope.split() if s in ALLOWED_SCOPES]
        if not requested_scopes:
            requested_scopes = list(self.config.default_scope)

        # Scopes that can be granted: requested ∩ FACADE_MAX_SCOPE (plus offline_access allowed)
        grantable = set(requested_scopes) & self.config.max_scope
        if "offline_access" in requested_scopes:
            grantable.add("offline_access")

        if "mindhub:read" not in grantable:
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=invalid_scope")
            return _redirect_error(
                redirect_uri,
                "invalid_scope",
                "mindhub:read scope is required",
                state,
                iss,
            )

        # Cap total pending authorizations (e.g. 200 unexpired rows)
        if self.store.count_active_pending_authorizations() >= 200:
            self.store.log_audit("authorize_rejected", client_id=client_id, detail="reason=pending_cap_exceeded")
            return _html_error(429, "Too Many Requests", "Too many pending authorization requests. Please try again later.")

        # Step 6: Create pending authorization
        request_id = generate_secret(32)
        csrf = generate_secret(32)
        granted_scope_str = " ".join(sorted(grantable))

        self.store.create_pending_authorization(
            request_id=request_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            scope=granted_scope_str,
            resource=self.config.resource,
            csrf=csrf,
            ttl_seconds=600,
        )

        # Step 7: Render consent page
        can_write = "mindhub:write" in grantable
        resp = render_consent_page(
            client_name=client.client_name or client.client_id,
            redirect_uri=redirect_uri,
            request_id=request_id,
            csrf=csrf,
            can_write=can_write,
        )
        resp.set_cookie(
            key="mh_csrf",
            value=csrf,
            max_age=600,
            path="/authorize",
            httponly=True,
            samesite="lax",
            secure=not self.config.allow_insecure_local,
        )
        return resp

    # -----------------------------------------------------------------------
    # Authorize Decision (POST /authorize/decision)
    # -----------------------------------------------------------------------

    def _redirect_response(self, redirect_uri: str, target: str) -> Response:
        try:
            hostname = (urllib.parse.urlsplit(redirect_uri).hostname or "").lower()
        except Exception:
            hostname = ""

        if self.config.google_meta_refresh and hostname.endswith(".googleusercontent.com"):
            return render_meta_refresh_response(target)
        return RedirectResponse(target, status_code=302, headers={"Cache-Control": "no-store"})

    async def authorize_decision(self, request: Request) -> Response:
        content_type = request.headers.get("content-type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type != "application/x-www-form-urlencoded":
            return render_html_error(
                400, "Invalid Request", "Content-Type must be application/x-www-form-urlencoded"
            )

        try:
            body_bytes = await read_capped_body(request, 16384)
        except PayloadTooLargeError:
            return render_html_error(413, "Payload Too Large", "Request body exceeds maximum size (16 KiB)")
        except InvalidContentLengthError:
            return render_html_error(400, "Invalid Request", "Invalid Content-Length header")

        try:
            form = parse_form_urlencoded(body_bytes, self.config.resource)
        except FormParseError as exc:
            return render_html_error(400, "Invalid Request", exc.description)

        request_id = form.get("request_id", "")
        csrf = form.get("csrf", "")
        password = form.get("password", "")
        scope_choice = form.get("scope_choice", "read")
        action = form.get("action", "deny")

        # 1. CSRF double-submit check (hidden field == cookie mh_csrf; constant-time)
        cookie_csrf = request.cookies.get("mh_csrf", "")
        if not csrf or not cookie_csrf or not hmac.compare_digest(cookie_csrf, csrf):
            return render_html_error(
                400, "CSRF verification failed", "CSRF token missing or mismatch."
            )

        # 2. Validate request_id and match stored CSRF hash (without marking used yet)
        pending = self.store.get_pending_authorization(request_id, csrf)
        if pending is None:
            return render_html_error(
                400,
                "Invalid authorization request",
                "The authorization request is invalid, expired, or has already been used.",
            )

        # 3. Handle deny (any action != "allow" is treated as deny)
        if action != "allow":
            consumed = self.store.consume_pending_authorization(request_id, csrf)
            if consumed is None:
                return render_html_error(
                    400,
                    "Invalid authorization request",
                    "The authorization request could not be processed.",
                )
            self.store.log_audit("authorization_denied", client_id=pending.client_id, detail="user_denied")
            params: dict[str, str] = {
                "error": "access_denied",
                "error_description": "User denied authorization",
                "iss": self.config.issuer,
            }
            if pending.state is not None:
                params["state"] = pending.state

            sep = "&" if "?" in pending.redirect_uri else "?"
            target = f"{pending.redirect_uri}{sep}{urllib.parse.urlencode(params)}"
            return self._redirect_response(pending.redirect_uri, target)

        # 4. Handle allow: Lockout check first (per-IP 5/15min, global 20/15min)
        ip = extract_client_ip(request, self.config.trust_cf_headers)
        now = self.store.now
        if self.ip_lockout.is_locked(ip, now) or self.global_lockout.is_locked("global", now):
            lock_type = "ip" if self.ip_lockout.is_locked(ip, now) else "global"
            self.store.log_audit("login_locked", client_id=pending.client_id, detail=f"type={lock_type} ip={ip}")
            return render_html_error(
                429,
                "Too Many Requests",
                "Too many failed login attempts. Please try again in 15 minutes.",
            )

        # 5. Password check
        if not verify_password(password, self.config.owner_password_hash):
            self.ip_lockout.record_failure(ip, now)
            self.global_lockout.record_failure("global", now)
            self.store.log_audit("login_failed", client_id=pending.client_id, detail=f"ip={ip}")
            await asyncio.sleep(0.05)  # small fixed delay on failure
            return render_html_error(
                401,
                "Unauthorized",
                "Incorrect owner password.",
            )

        # 6. Atomically consume pending authorization (single-use)
        consumed = self.store.consume_pending_authorization(request_id, csrf)
        if consumed is None:
            return render_html_error(
                400,
                "Invalid authorization request",
                "The authorization request was already processed or expired.",
            )

        # 7. Calculate granted scope: (scope_choice mapped) ∩ requested ∩ FACADE_MAX_SCOPE
        pending_scopes = set(pending.scope.split())
        if scope_choice == "readwrite":
            chosen = {"mindhub:read", "mindhub:write"}
        else:
            chosen = {"mindhub:read"}

        granted_set = chosen & pending_scopes & self.config.max_scope
        if "offline_access" in pending_scopes:
            granted_set.add("offline_access")
        granted_scope_str = " ".join(sorted(granted_set))

        # 8. Create auth code (TTL FACADE_CODE_TTL_SECONDS, bound parameters, new family_id)
        code = generate_secret(32)
        family_id = f"fam_{generate_secret(16)}"
        self.store.create_auth_code(
            code=code,
            client_id=pending.client_id,
            redirect_uri=pending.redirect_uri,
            code_challenge=pending.code_challenge,
            scope=granted_scope_str,
            resource=pending.resource,
            family_id=family_id,
            ttl_seconds=self.config.code_ttl_seconds,
        )
        self.store.log_audit("authorization_granted", client_id=pending.client_id, detail=f"scope={granted_scope_str}")

        # 9. Redirect (Google meta-refresh or 302, Cache-Control: no-store)
        params = {
            "code": code,
            "iss": self.config.issuer,
        }
        if pending.state is not None:
            params["state"] = pending.state

        sep = "&" if "?" in pending.redirect_uri else "?"
        target = f"{pending.redirect_uri}{sep}{urllib.parse.urlencode(params)}"
        return self._redirect_response(pending.redirect_uri, target)

    # -----------------------------------------------------------------------
    # Token (POST /token)
    # -----------------------------------------------------------------------

    async def token(self, request: Request) -> Response:
        ip = extract_client_ip(request, self.config.trust_cf_headers)
        if not self.token_limiter.check(ip, now_fn=lambda: self.store.now):
            return JSONResponse(
                {"error": "rate_limited"},
                status_code=429,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        content_type = request.headers.get("content-type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type != "application/x-www-form-urlencoded":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "application/x-www-form-urlencoded is required"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        try:
            body_bytes = await read_capped_body(request, 16384)
        except PayloadTooLargeError:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Request body exceeds maximum size (16 KiB)"},
                status_code=413,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        except InvalidContentLengthError:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid Content-Length header"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        try:
            form = parse_form_urlencoded(body_bytes, self.config.resource)
        except FormParseError as exc:
            return JSONResponse(
                {"error": "invalid_request", "error_description": exc.description},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        grant_type = form.get("grant_type", "")

        # Extract client_id: body wins over Basic auth header
        client_id = form.get("client_id")
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
                    client_id = decoded.split(":", 1)[0]
                except Exception:
                    pass

        if not client_id:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client identification is required"},
                status_code=401,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        client = self.store.get_client(client_id)
        if client is None:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Unknown or revoked client"},
                status_code=401,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        if grant_type == "authorization_code":
            return await self._handle_authorization_code_grant(form, client_id)
        elif grant_type == "refresh_token":
            return await self._handle_refresh_token_grant(form, client_id)
        else:
            clean_grant_type = "".join(c if (32 <= ord(c) <= 126) else "?" for c in grant_type[:64])
            return JSONResponse(
                {"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type: {clean_grant_type}"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

    async def _handle_authorization_code_grant(self, form: dict[str, str], client_id: str) -> Response:
        code = form.get("code", "")
        verifier = form.get("code_verifier", "")
        redirect_uri = form.get("redirect_uri", "")
        resource = form.get("resource")

        if not code or not verifier or not redirect_uri:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "code, code_verifier, and redirect_uri are required"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 1. Find code, check expiry, atomically consume (used -> revoke family + audit + invalid_grant)
        rec, is_replay = self.store.consume_auth_code(code)
        if is_replay:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Authorization code has already been used"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        if rec is None:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Authorization code is invalid or expired"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 2. client_id match
        if rec.client_id != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Client mismatch"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 3. redirect_uri match
        if rec.redirect_uri != redirect_uri:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 4. resource match
        if resource is not None and (resource != self.config.resource or resource != rec.resource):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Target resource mismatch"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 5. THEN validate verifier syntax (43-128 chars, [A-Za-z0-9-._~])
        if not validate_code_verifier(verifier):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid code_verifier format"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 6. PKCE compare
        if not verify_pkce(verifier, rec.code_challenge, method="S256"):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # Issue access and refresh tokens
        access_tok = generate_secret(32)
        refresh_tok = generate_secret(32)

        self.store.create_token(
            token=access_tok,
            kind="access",
            client_id=client_id,
            scope=rec.scope,
            resource=rec.resource,
            family_id=rec.family_id,
            ttl_seconds=self.config.access_ttl_seconds,
        )
        self.store.create_token(
            token=refresh_tok,
            kind="refresh",
            client_id=client_id,
            scope=rec.scope,
            resource=rec.resource,
            family_id=rec.family_id,
            ttl_seconds=self.config.refresh_ttl_seconds,
        )
        self.store.touch_client(client_id)
        self.store.log_audit("token_issued", client_id=client_id, detail=f"grant_type=authorization_code scope={rec.scope}")

        resp_data = {
            "access_token": access_tok,
            "token_type": "Bearer",
            "expires_in": self.config.access_ttl_seconds,
            "refresh_token": refresh_tok,
            "scope": rec.scope,
        }
        return JSONResponse(
            resp_data,
            status_code=200,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    async def _handle_refresh_token_grant(self, form: dict[str, str], client_id: str) -> Response:
        refresh_token = form.get("refresh_token", "")
        requested_scope = form.get("scope")
        resource = form.get("resource")

        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "refresh_token is required"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 1. Non-consuming peek
        rec = self.store.peek_refresh_token(refresh_token)
        if rec is None:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token is invalid"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 2. Check expiry
        if rec.expires_at <= self.store.now:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token is expired"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 3. Check replay or revoked (triggers family revocation)
        if rec.used or rec.revoked:
            self.store.revoke_family(rec.family_id, reason="refresh_token_reuse")
            self.store.log_audit("refresh_token_reuse", client_id=rec.client_id, detail="family revoked")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token was already used or revoked"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 4. Client match (returns error WITHOUT burning token or revoking family)
        if rec.client_id != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Client mismatch for refresh token"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 5. Resource match (returns error WITHOUT burning token)
        if resource is not None and (resource != self.config.resource or resource != rec.resource):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Resource mismatch"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 6. Scope narrowing check (returns error WITHOUT burning token)
        original_scopes = set(rec.scope.split())
        granted_scope = original_scopes
        if requested_scope is not None:
            stripped = requested_scope.strip()
            if stripped:
                req_set = set(stripped.split())
                if not req_set or not req_set.issubset(original_scopes) or "mindhub:read" not in req_set:
                    return JSONResponse(
                        {"error": "invalid_scope", "error_description": "Invalid requested scope on refresh"},
                        status_code=400,
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
                    )
                granted_scope = req_set

        granted_scope_str = " ".join(sorted(granted_scope))

        # 7. Atomic consume (rowcount == 1, else treat as replay and revoke family)
        success = self.store.atomic_consume_refresh_token(refresh_token, rec.family_id)
        if not success:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token was already used or revoked"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        # 8. Rotate tokens
        new_access = generate_secret(32)
        new_refresh = generate_secret(32)

        self.store.create_token(
            token=new_access,
            kind="access",
            client_id=client_id,
            scope=granted_scope_str,
            resource=rec.resource,
            family_id=rec.family_id,
            ttl_seconds=self.config.access_ttl_seconds,
        )
        self.store.create_token(
            token=new_refresh,
            kind="refresh",
            client_id=client_id,
            scope=granted_scope_str,
            resource=rec.resource,
            family_id=rec.family_id,
            ttl_seconds=self.config.refresh_ttl_seconds,
        )
        self.store.touch_client(client_id)
        self.store.log_audit("token_refreshed", client_id=client_id, detail=f"grant_type=refresh_token scope={granted_scope_str}")

        resp_data = {
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": self.config.access_ttl_seconds,
            "refresh_token": new_refresh,
            "scope": granted_scope_str,
        }
        return JSONResponse(
            resp_data,
            status_code=200,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    # -----------------------------------------------------------------------
    # Revoke (POST /revoke, RFC 7009)
    # -----------------------------------------------------------------------

    async def revoke(self, request: Request) -> Response:
        content_type = request.headers.get("content-type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type != "application/x-www-form-urlencoded":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "application/x-www-form-urlencoded is required"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        try:
            body_bytes = await read_capped_body(request, 16384)
        except PayloadTooLargeError:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Request body exceeds maximum size (16 KiB)"},
                status_code=413,
                headers={"Cache-Control": "no-store"},
            )
        except InvalidContentLengthError:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid Content-Length header"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        try:
            form = parse_form_urlencoded(body_bytes, self.config.resource)
        except FormParseError as exc:
            return JSONResponse(
                {"error": "invalid_request", "error_description": exc.description},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )

        token = form.get("token", "")
        client_id = form.get("client_id")

        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
                    client_id = decoded.split(":", 1)[0]
                except Exception:
                    pass

        if token and client_id:
            revoked = self.store.revoke_token(token, client_id=client_id)
            if revoked:
                self.store.touch_client(client_id)
                self.store.log_audit("token_revoked", client_id=client_id, detail="revoked")

        # RFC 7009 specifies returning HTTP 200 regardless of whether token existed
        return Response(content="", status_code=200, headers={"Cache-Control": "no-store"})
