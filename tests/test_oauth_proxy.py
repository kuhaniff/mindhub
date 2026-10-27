"""Unit tests for Resource Server and Proxy (/mcp)."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from mindhub_oauth._http import httpx
from mindhub_oauth.app import create_app
from mindhub_oauth.config import Config
from mindhub_oauth.security import hash_password
from mindhub_oauth.store import OAuthStore


class FakeUpstreamApp:
    """Fake upstream server that records received requests."""

    def __init__(self) -> None:
        self.last_method: str | None = None
        self.last_headers: dict[str, str] = {}
        self.raw_headers: list[tuple[bytes, bytes]] = []
        self.delay_seconds: float = 0.0
        self.last_body: bytes = b""
        self.response_status = 200
        self.response_headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            "Server": "FakeUpstream/1.0",
            "Set-Cookie": "secret_cookie=xyz; Path=/",
            "WWW-Authenticate": "Basic realm=fake",
            "Mcp-Session-Id": "sess_123",
            "MCP-Protocol-Version": "2024-11-05",
        }
        self.response_body: bytes = b'{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}'

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return

        self.last_method = scope["method"]
        self.raw_headers = list(scope.get("headers", []))
        headers = {}
        for raw_k, raw_v in scope.get("headers", []):
            headers[raw_k.decode("latin1").lower()] = raw_v.decode("latin1")
        self.last_headers = headers

        body = bytearray()
        while True:
            msg = await receive()
            body.extend(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        self.last_body = bytes(body)

        if self.delay_seconds > 0.0:
            await asyncio.sleep(self.delay_seconds)

        # Build response headers
        resp_headers = []
        for k, v in self.response_headers.items():
            resp_headers.append((k.encode("latin1"), v.encode("latin1")))

        await send({
            "type": "http.response.start",
            "status": self.response_status,
            "headers": resp_headers,
        })
        await send({
            "type": "http.response.body",
            "body": self.response_body,
            "more_body": False,
        })


class TestOAuthProxy(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_proxy.db")
        self.current_time = 1000.0
        self.store = OAuthStore(self.db_path, now_fn=lambda: self.current_time)

        self.upstream = FakeUpstreamApp()
        self.upstream_transport = httpx.ASGITransport(app=self.upstream)
        self.http_client = httpx.AsyncClient(
            transport=self.upstream_transport,
            base_url="http://127.0.0.1:8088",
        )

        self.config = Config.from_env(
            {
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": "http://127.0.0.1:8088/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "internal-secret-upstream-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_MAX_SCOPE": "mindhub:read mindhub:write",
                "FACADE_DEFAULT_SCOPE": "mindhub:read",
                "FACADE_DB_PATH": self.db_path,
            }
        )

        self.app = create_app(self.config, store=self.store, http_client=self.http_client)
        self.client = TestClient(self.app)

        # Create valid client & tokens
        self.client_id = "test_client_mcp"
        self.store.create_client(
            client_id=self.client_id,
            client_name="MCP App",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        self.token_read = "tok_access_read_123"
        self.store.create_token(
            token=self.token_read,
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read",
            resource=self.config.resource,
            family_id="fam_mcp_1",
            ttl_seconds=3600,
        )
        self.token_write = "tok_access_write_456"
        self.store.create_token(
            token=self.token_write,
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read mindhub:write",
            resource=self.config.resource,
            family_id="fam_mcp_2",
            ttl_seconds=3600,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_unauthenticated_head_returns_401_with_www_auth_and_no_body(self) -> None:
        # Per M4-1: HEAD without valid token => 401 + exact WWW-Authenticate header, no body
        res = self.client.head("/mcp")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.text, "")
        www_auth = res.headers.get("www-authenticate", "")
        self.assertIn("Bearer", www_auth)
        self.assertIn('resource_metadata="https://mindhub.example.com/.well-known/oauth-protected-resource"', www_auth)
        self.assertIn('scope="mindhub:read"', www_auth)
        self.assertNotIn("error=", www_auth)

    def test_unauthenticated_get_post_delete_return_401_with_www_auth(self) -> None:
        for m in ["get", "post", "delete"]:
            method = getattr(self.client, m)
            res = method("/mcp")
            self.assertEqual(res.status_code, 401)
            www_auth = res.headers.get("www-authenticate", "")
            self.assertIn("Bearer", www_auth)
            self.assertEqual(res.json(), {"error": "unauthorized"})

    def test_unsupported_methods_return_405_with_allow_header(self) -> None:
        for m in ["put", "patch", "options"]:
            method = getattr(self.client, m)
            res = method("/mcp")
            self.assertEqual(res.status_code, 405)
            allow = res.headers.get("allow", "")
            for expected in ["POST", "GET", "DELETE", "HEAD"]:
                self.assertIn(expected, allow)

    def test_query_string_token_rejected_with_401(self) -> None:
        # Tokens in query string are NEVER accepted
        res1 = self.client.get(f"/mcp?token={self.token_read}")
        self.assertEqual(res1.status_code, 401)

        res2 = self.client.get(f"/mcp?access_token={self.token_read}")
        self.assertEqual(res2.status_code, 401)

    def test_invalid_expired_revoked_token_returns_401_invalid_token(self) -> None:
        # Invalid token
        res = self.client.get("/mcp", headers={"Authorization": "Bearer bad_tok_xyz"})
        self.assertEqual(res.status_code, 401)
        self.assertIn('error="invalid_token"', res.headers.get("www-authenticate", ""))
        self.assertEqual(res.json(), {"error": "invalid_token"})

        # Expired token
        self.current_time += 7200.0
        res_exp = self.client.get("/mcp", headers={"Authorization": f"Bearer {self.token_read}"})
        self.assertEqual(res_exp.status_code, 401)
        self.assertIn('error="invalid_token"', res_exp.headers.get("www-authenticate", ""))

    def test_authenticated_head_returns_200_with_no_body(self) -> None:
        # M4-1: HEAD with valid token must not stream a body
        res = self.client.head("/mcp", headers={"Authorization": f"Bearer {self.token_read}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, "")

    def test_request_body_size_cap_1mib(self) -> None:
        # Exactly 1 MiB + 10 bytes
        oversize = b"x" * (1024 * 1024 + 10)
        res = self.client.post(
            "/mcp",
            content=oversize,
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 413)
        self.assertEqual(res.json(), {"error": "payload_too_large"})

    def test_request_headers_forwarded_and_stripped(self) -> None:
        # Client sends various headers
        client_headers = {
            "Authorization": f"Bearer {self.token_read}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Session-Id": "client_session_xyz",
            "MCP-Protocol-Version": "2024-11-05",
            "Last-Event-ID": "event_99",
            # Headers that MUST be stripped:
            "X-API-Key": "client_attempted_key",
            "Cookie": "client_cookie=abc",
            "X-Forwarded-For": "198.51.100.1",
            "CF-Connecting-IP": "198.51.100.2",
            "Host": "evil.com",
        }
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers=client_headers,
        )
        self.assertEqual(res.status_code, 200)

        # Check what fake upstream received
        received = self.upstream.last_headers
        # Stripped:
        self.assertNotIn("authorization", received)
        self.assertNotIn("cookie", received)
        self.assertNotIn("x-forwarded-for", received)
        self.assertNotIn("cf-connecting-ip", received)
        # Internal API key injected (client key replaced):
        self.assertEqual(received.get("x-api-key"), "internal-secret-upstream-key")
        # Allowed forwarded headers:
        self.assertEqual(received.get("content-type"), "application/json")
        self.assertEqual(received.get("accept"), "application/json, text/event-stream")
        self.assertEqual(received.get("mcp-session-id"), "client_session_xyz")
        self.assertEqual(received.get("mcp-protocol-version"), "2024-11-05")
        self.assertEqual(received.get("last-event-id"), "event_99")

    def test_response_headers_filtered(self) -> None:
        # Fake upstream returns Set-Cookie, Server, WWW-Authenticate
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers={"Authorization": f"Bearer {self.token_read}"},
        )
        self.assertEqual(res.status_code, 200)

        # Stripped from facade response:
        self.assertNotIn("set-cookie", res.headers)
        self.assertNotIn("server", res.headers)
        self.assertNotIn("www-authenticate", res.headers)

        # Allowed headers kept:
        self.assertEqual(res.headers.get("content-type"), "application/json")
        self.assertEqual(res.headers.get("cache-control"), "no-cache")
        self.assertEqual(res.headers.get("mcp-session-id"), "sess_123")
        self.assertEqual(res.headers.get("mcp-protocol-version"), "2024-11-05")

    def test_sse_response_adds_x_accel_buffering(self) -> None:
        self.upstream.response_headers["Content-Type"] = "text/event-stream"
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers={"Authorization": f"Bearer {self.token_read}"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("x-accel-buffering"), "no")

    def test_upstream_401_403_returns_502_upstream_auth_failure_and_audits(self) -> None:
        self.upstream.response_status = 401
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers={"Authorization": f"Bearer {self.token_read}"},
        )
        self.assertEqual(res.status_code, 502)
        self.assertEqual(res.json(), {"error": "upstream_auth_failure"})

        # Audit event recorded
        events = self.store.get_audit_events()
        self.assertTrue(any(e.event == "upstream_auth_failure" for e in events))

    def test_upstream_404_passthrough(self) -> None:
        self.upstream.response_status = 404
        self.upstream.response_body = b'{"error":"session not found"}'
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers={"Authorization": f"Bearer {self.token_read}"},
        )
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json(), {"error": "session not found"})

    def test_non_allowlisted_methods_and_notifications_not_forwarded_upstream(self) -> None:
        forbidden = [
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "tasks/create",
            "tasks/get",
            "completion/complete",
            "logging/setLevel",
        ]
        for idx, m in enumerate(forbidden, start=1):
            self.upstream.last_body = b""
            res = self.client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {self.token_read}"},
                json={"jsonrpc": "2.0", "id": idx, "method": m},
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data.get("id"), idx)
            self.assertEqual(data.get("error", {}).get("code"), -32601)
            self.assertEqual(self.upstream.last_body, b"")

        # Notifications without id
        for m in ["notifications/progress", "notifications/message"]:
            self.upstream.last_body = b""
            res = self.client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {self.token_read}"},
                json={"jsonrpc": "2.0", "method": m},
            )
            self.assertEqual(res.status_code, 202)
            self.assertEqual(res.text, "")
            self.assertEqual(self.upstream.last_body, b"")

    def test_lone_surrogates_and_escapes_upstream_pure_ascii(self) -> None:
        # 1. Lone surrogate in string value
        self.upstream.last_body = b""
        raw1 = br'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"val": "\ud800"}}'
        res1 = self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
            content=raw1,
        )
        self.assertEqual(res1.status_code, 200)
        self.assertTrue(self.upstream.last_body.isascii())
        self.assertIn(b'"\\ud800"', self.upstream.last_body)

        # 2. Lone surrogate in key
        self.upstream.last_body = b""
        raw2 = br'{"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"\ud800": "val"}}'
        res2 = self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
            content=raw2,
        )
        self.assertEqual(res2.status_code, 200)
        self.assertTrue(self.upstream.last_body.isascii())

        # 3. Non-BMP emoji (\ud83d\ude00)
        self.upstream.last_body = b""
        raw3 = br'{"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {"emoji": "\ud83d\ude00"}}'
        res3 = self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
            content=raw3,
        )
        self.assertEqual(res3.status_code, 200)
        self.assertTrue(self.upstream.last_body.isascii())
        self.assertIn(b'"\\ud83d\\ude00"', self.upstream.last_body)

        # 4. Escaped params.name: \u0073earch_memory -> normalized after parsing to search_memory
        self.upstream.last_body = b""
        raw4 = br'{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "\u0073earch_memory"}}'
        res4 = self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
            content=raw4,
        )
        self.assertEqual(res4.status_code, 200)
        parsed = json.loads(self.upstream.last_body.decode("ascii"))
        self.assertEqual(parsed["params"]["name"], "search_memory")

        # 5. Lone surrogate in params.name: search_memory\ud800 -> denied after parsing
        self.upstream.last_body = b""
        raw5 = br'{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "search_memory\ud800"}}'
        res5 = self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
            content=raw5,
        )
        self.assertEqual(res5.status_code, 200)
        self.assertEqual(res5.json().get("error", {}).get("code"), -32001)
        self.assertEqual(self.upstream.last_body, b"")

    def test_serve_cli_uvicorn_kwargs(self) -> None:
        from mindhub_oauth.__main__ import serve_cli

        env = {
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "MINDHUB_UPSTREAM_API_KEY": "test-key",
            "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
            "FACADE_DB_PATH": "/tmp/serve_test.db",
        }
        with patch.dict(os.environ, env):
            with patch("uvicorn.run") as mock_run:
                serve_cli([])
                mock_run.assert_called_once()
                _, kwargs = mock_run.call_args
                self.assertEqual(kwargs.get("proxy_headers"), False)
                self.assertEqual(kwargs.get("server_header"), False)
                self.assertEqual(kwargs.get("date_header"), True)
                self.assertEqual(kwargs.get("access_log"), False)
                self.assertEqual(kwargs.get("lifespan"), "on")
                self.assertEqual(kwargs.get("timeout_graceful_shutdown"), 5)
                self.assertEqual(kwargs.get("host"), "127.0.0.1")
                self.assertEqual(kwargs.get("port"), 8089)

    def test_p4_upstream_headers_strict_allowlist_and_single_content_type(self) -> None:
        client_headers = {
            "Authorization": f"Bearer {self.token_read}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Mcp-Session-Id": "sess_abc",
            "Cookie": "secret_cookie=foo",
            "Host": "evil.example.com",
            "X-Forwarded-For": "10.0.0.1",
        }
        res = self.client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            headers=client_headers,
        )
        self.assertEqual(res.status_code, 200)

        # Verify exactly ONE content-type header sent upstream
        raw_ct = [k for k, v in self.upstream.raw_headers if k.lower() == b"content-type"]
        self.assertEqual(len(raw_ct), 1)

        # Verify forbidden headers stripped
        self.assertNotIn("authorization", self.upstream.last_headers)
        self.assertNotIn("cookie", self.upstream.last_headers)
        self.assertNotIn("x-forwarded-for", self.upstream.last_headers)
        # Client host replaced with upstream target host
        self.assertNotEqual(self.upstream.last_headers.get("host"), "evil.example.com")
        # Internal API key injected
        self.assertEqual(self.upstream.last_headers.get("x-api-key"), "internal-secret-upstream-key")

    def test_p5_upstream_transport_error_returns_502_with_jsonrpc_32603(self) -> None:
        cfg = Config.from_env({
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "FACADE_UPSTREAM_URL": "http://127.0.0.1:59999/mcp",
            "MINDHUB_UPSTREAM_API_KEY": "test-key",
            "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
            "FACADE_DB_PATH": self.db_path,
        })
        app = create_app(cfg, store=self.store)
        client = TestClient(app)
        res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {self.token_read}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        self.assertEqual(res.status_code, 502)
        data = res.json()
        self.assertEqual(data.get("jsonrpc"), "2.0")
        self.assertEqual(data.get("error", {}).get("code"), -32603)

    def test_p5_upstream_timeout_returns_504_with_jsonrpc_32603(self) -> None:
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            cfg = Config.from_env({
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{port}/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_DB_PATH": self.db_path,
            })
            fast_timeout_client = httpx.AsyncClient(
                timeout=httpx.Timeout(0.05, connect=0.05, read=0.05),
            )
            app = create_app(cfg, store=self.store, http_client=fast_timeout_client)
            client = TestClient(app)
            res = client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {self.token_read}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            self.assertEqual(res.status_code, 504)
            data = res.json()
            self.assertEqual(data.get("jsonrpc"), "2.0")
            self.assertEqual(data.get("error", {}).get("code"), -32603)
        finally:
            s.close()

    def test_p6_get_and_delete_with_body_forwards_empty_body_to_upstream(self) -> None:
        self.upstream.last_body = b"non_empty_init"
        res_get = self.client.request(
            "GET",
            "/mcp",
            content=b'{"evil":"body_in_get"}',
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
        )
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(self.upstream.last_body, b"")

        self.upstream.last_body = b"non_empty_init"
        res_del = self.client.request(
            "DELETE",
            "/mcp",
            content=b'{"evil":"body_in_delete"}',
            headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
        )
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(self.upstream.last_body, b"")

    def test_p9_app_lifespan_triggers_proxy_start_and_shutdown(self) -> None:
        import sqlite3
        db_file = os.path.join(self.temp_dir.name, "lifespan_test.db")
        cfg = Config.from_env({
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "FACADE_UPSTREAM_URL": "http://127.0.0.1:8088/mcp",
            "MINDHUB_UPSTREAM_API_KEY": "test-key",
            "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
            "FACADE_DB_PATH": db_file,
        })
        app = create_app(cfg)
        proxy = app.state.proxy
        store = app.state.store
        self.assertIsNone(proxy._client)

        with TestClient(app):
            # Lifespan startup should have run
            self.assertIsNotNone(proxy._client)

        # Lifespan shutdown should have run
        self.assertIsNone(proxy._client)
        with self.assertRaises(sqlite3.ProgrammingError):
            store._conn.execute("SELECT 1")

    def test_real_mindhub_app_5_tools_listed_through_proxy(self) -> None:
        # Check if mindhub.server.create_app is importable
        try:
            from mindhub.server import create_app as create_mindhub_app
        except ImportError as e:
            self.skipTest(f"mindhub.server not importable: {e}")

        # Create real Mindhub app with internal API key (MINDHUB_API_KEYS)
        async def run_test():
            with patch.dict(os.environ, {"MINDHUB_API_KEYS": "internal-secret-upstream-key"}):
                real_mindhub = create_mindhub_app()

                async with real_mindhub.router.lifespan_context(real_mindhub):
                    real_transport = httpx.ASGITransport(app=real_mindhub)
                    async with httpx.AsyncClient(
                        transport=real_transport,
                        base_url="http://127.0.0.1:8088",
                    ) as client_to_real:
                        app = create_app(self.config, store=self.store, http_client=client_to_real)
                        facade_transport = httpx.ASGITransport(app=app)
                        async with httpx.AsyncClient(
                            transport=facade_transport,
                            base_url="https://mindhub.example.com",
                        ) as facade_client:
                            # 1. Initialize through facade proxy
                            init_res = await facade_client.post(
                                "/mcp",
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "initialize",
                                    "params": {
                                        "protocolVersion": "2024-11-05",
                                        "capabilities": {},
                                        "clientInfo": {"name": "test", "version": "1.0"},
                                    },
                                },
                                headers={
                                    "Authorization": f"Bearer {self.token_read}",
                                    "Accept": "application/json, text/event-stream",
                                },
                            )
                            self.assertEqual(init_res.status_code, 200)
                            sess_id = init_res.headers.get("mcp-session-id")
                            self.assertIsNotNone(sess_id)

                            # 2. Call tools/list through facade proxy
                            req_body = {
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/list",
                            }
                            res = await facade_client.post(
                                "/mcp",
                                json=req_body,
                                headers={
                                    "Authorization": f"Bearer {self.token_read}",
                                    "Mcp-Session-Id": sess_id,
                                    "Accept": "application/json, text/event-stream",
                                },
                            )
                            self.assertEqual(res.status_code, 200)
                            text = res.text
                            if "data: " in text:
                                data_line = [line for line in text.splitlines() if line.startswith("data: ")][0]
                                data = json.loads(data_line[6:])
                            else:
                                data = res.json()

                            self.assertIn("result", data)
                            tools = data["result"].get("tools", [])
                            tool_names = {t["name"] for t in tools}

                            expected_tools = {
                                "search_memory",
                                "remember",
                                "get_project_state",
                                "update_project_state",
                                "get_project_state_history",
                            }
                            self.assertEqual(tool_names, expected_tools)
                            self.assertEqual(len(tools), 5)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
