"""Streaming reverse proxy and Resource Server for /mcp."""
from __future__ import annotations

import json
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

from ._http import httpx
from .config import Config
from .policy import evaluate_policy
from .store import OAuthStore

UPSTREAM_HEADER_ALLOWLIST = frozenset({
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
})

RESPONSE_HEADER_ALLOWLIST = frozenset({
    "content-type",
    "cache-control",
    "mcp-session-id",
    "mcp-protocol-version",
})

MAX_BODY_SIZE = 1024 * 1024  # 1 MiB


def _json_response(
    data: Any,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Return an application/json response using ensure_ascii=True (pure ASCII)."""
    content = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    resp_headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    if headers:
        resp_headers.update(headers)
    return Response(
        content,
        status_code=status_code,
        media_type="application/json",
        headers=resp_headers,
    )


class OAuthProxy:
    """Resource Server and Reverse Proxy handler for /mcp."""

    def __init__(
        self,
        config: Config,
        store: OAuthStore,
        http_client: Any | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self._custom_client = http_client
        self._owned_client: Any | None = None
        self._client: Any | None = http_client

    async def start(self) -> None:
        """Initialize the HTTP client at application startup (prevent lazy-creation race)."""
        if self._custom_client is not None:
            self._client = self._custom_client
        elif self._owned_client is None:
            timeout = httpx.Timeout(120.0, connect=5.0, write=30.0, pool=5.0)
            self._owned_client = httpx.AsyncClient(timeout=timeout)
            self._client = self._owned_client

    def _get_http_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._custom_client is not None:
            return self._custom_client
        if self._owned_client is None:
            timeout = httpx.Timeout(120.0, connect=5.0, write=30.0, pool=5.0)
            self._owned_client = httpx.AsyncClient(timeout=timeout)
            self._client = self._owned_client
        return self._owned_client

    async def aclose(self) -> None:
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None
            self._client = None

    async def handle_mcp(self, request: Request) -> Response:
        method = request.method

        # M4-1. Methods: /mcp must handle POST, GET, DELETE and HEAD
        if method not in ("POST", "GET", "DELETE", "HEAD"):
            return Response(
                "Method Not Allowed",
                status_code=405,
                headers={"Allow": "POST, GET, DELETE, HEAD"},
            )

        # 8.1 Authentication: Bearer token in Authorization header
        auth_header = request.headers.get("Authorization", "")
        # Query string tokens are NEVER accepted
        has_query_token = (
            "token" in request.query_params or "access_token" in request.query_params
        )

        default_scope_str = " ".join(sorted(self.config.default_scope))
        missing_token = not auth_header or not auth_header.lower().startswith("bearer ") or has_query_token

        if missing_token:
            www_auth = (
                f'Bearer resource_metadata="{self.config.issuer}/.well-known/oauth-protected-resource", '
                f'scope="{default_scope_str}"'
            )
            if method == "HEAD":
                return Response(
                    "",
                    status_code=401,
                    headers={"WWW-Authenticate": www_auth, "Cache-Control": "no-store"},
                )
            return _json_response(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": www_auth},
            )

        token = auth_header[7:].strip()
        rec = self.store.get_access_token(token)

        invalid = (
            rec is None
            or rec.kind != "access"
            or rec.revoked
            or rec.expires_at <= self.store.now
            or rec.resource != self.config.resource
        )

        if invalid:
            www_auth = (
                f'Bearer error="invalid_token", '
                f'resource_metadata="{self.config.issuer}/.well-known/oauth-protected-resource", '
                f'scope="{default_scope_str}"'
            )
            if method == "HEAD":
                return Response(
                    "",
                    status_code=401,
                    headers={"WWW-Authenticate": www_auth, "Cache-Control": "no-store"},
                )
            return _json_response(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": www_auth},
            )

        # M4-1: HEAD with a valid token must return 200 without streaming a body
        if method == "HEAD":
            return Response("", status_code=200, headers={"Cache-Control": "no-store"})

        # Request body size cap (1 MiB)
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                cl = int(content_length)
                if cl > MAX_BODY_SIZE:
                    return _json_response({"error": "payload_too_large"}, status_code=413)
            except ValueError:
                return _json_response({"error": "invalid_request"}, status_code=400)

        # Read body with request.stream() keeping a running total
        total_bytes = 0
        body_chunks: list[bytes] = []
        is_oversized = False
        async for chunk in request.stream():
            total_bytes += len(chunk)
            if total_bytes > MAX_BODY_SIZE:
                is_oversized = True
                break
            body_chunks.append(chunk)

        if is_oversized:
            return _json_response({"error": "payload_too_large"}, status_code=413)

        body_bytes = b"".join(body_chunks)

        # Policy evaluation on POST requests; GET/DELETE never forward a body
        payload_to_send: bytes | None = None
        if method == "POST":
            status_code, body_or_forward, action = evaluate_policy(body_bytes, rec.scope)
            if action == "respond":
                if status_code == 202:
                    return Response("", status_code=202, headers={"Cache-Control": "no-store"})
                return _json_response(body_or_forward, status_code=status_code)
            assert isinstance(body_or_forward, bytes)
            payload_to_send = body_or_forward
        elif method in ("GET", "DELETE"):
            payload_to_send = None

        # Prepare request headers to send upstream (lowercase keys, strict allowlist)
        headers_to_send: dict[str, str] = {}
        for k, v in request.headers.items():
            k_lower = k.lower()
            if k_lower in UPSTREAM_HEADER_ALLOWLIST and k_lower != "content-type":
                headers_to_send[k_lower] = v

        if method == "POST":
            headers_to_send["content-type"] = "application/json"

        # Inject internal Mindhub upstream API key with lowercase key
        headers_to_send["x-api-key"] = self.config.upstream_api_key

        # Send request to upstream
        client = self._get_http_client()
        upstream_url = self.config.upstream_url

        try:
            upstream_req = client.build_request(
                method=method,
                url=upstream_url,
                headers=headers_to_send,
                content=payload_to_send,
            )
            upstream_resp = await client.send(upstream_req, stream=True)
        except httpx.TimeoutException:
            return _json_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": "Gateway timeout: upstream request timed out"},
                },
                status_code=504,
            )
        except (httpx.TransportError, httpx.HTTPError):
            return _json_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": "Bad gateway: upstream connection error"},
                },
                status_code=502,
            )

        # Upstream 401/403 -> return 502 upstream_auth_failure + audit
        if upstream_resp.status_code in (401, 403):
            await upstream_resp.aclose()
            self.store.log_audit(
                "upstream_auth_failure",
                client_id=rec.client_id,
                detail=f"status={upstream_resp.status_code}",
            )
            return _json_response(
                {"error": "upstream_auth_failure"},
                status_code=502,
            )

        # Prepare response headers returned to client (strict allowlist)
        client_headers: dict[str, str] = {}
        for k, v in upstream_resp.headers.items():
            if k.lower() in RESPONSE_HEADER_ALLOWLIST:
                client_headers[k] = v

        # Add X-Accel-Buffering: no for event streams (SSE)
        if "text/event-stream" in client_headers.get("content-type", "").lower():
            client_headers["X-Accel-Buffering"] = "no"

        # Stream upstream response to client without buffering
        is_event_stream = "text/event-stream" in client_headers.get("content-type", "").lower()

        async def stream_generator():
            try:
                async for chunk in upstream_resp.aiter_bytes():
                    yield chunk
            except (httpx.HTTPError, httpx.TimeoutException):
                if is_event_stream:
                    return
                raise
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            stream_generator(),
            status_code=upstream_resp.status_code,
            headers=client_headers,
        )
