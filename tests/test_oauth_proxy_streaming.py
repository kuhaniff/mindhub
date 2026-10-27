"""Real loopback socket streaming and security tests for OAuth proxy (/mcp).

Tests verify:
- Incremental SSE delivery without buffering (Amendment A4)
- Upstream connection teardown on client disconnect (Amendment A4)
- JSON smuggling defenses (duplicate keys, UTF-8 BOM, deep nesting)
- Re-serialized canonical JSON forwarding
- Method allowlist enforcement (-32601)
- Scope policy enforcement on tools/call (-32001)
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

from mindhub_oauth._http import httpx
from mindhub_oauth.app import create_app
from mindhub_oauth.config import Config
from mindhub_oauth.security import hash_password
from mindhub_oauth.store import OAuthStore


class StreamingFakeUpstream:
    """Fake upstream server supporting recording and deterministic streaming."""

    def __init__(self) -> None:
        self.last_headers: dict[str, str] = {}
        self.last_body: bytes = b""
        self.mode: str = "default"
        self.chunk1_received = threading.Event()
        self.upstream_disconnected = threading.Event()
        self.keepalive_count = 0

    async def handle_mcp(self, request: Request) -> Response:
        self.last_headers = {k.lower(): v for k, v in request.headers.items()}
        self.last_body = await request.body()

        if self.mode == "stream":
            async def event_generator():
                try:
                    yield b"data: chunk1\n\n"
                    # Deterministic wait: wait until test confirms chunk1 was received
                    await asyncio.to_thread(self.chunk1_received.wait, 10.0)
                    yield b"data: chunk2\n\n"
                except (asyncio.CancelledError, GeneratorExit):
                    self.upstream_disconnected.set()
                    raise
                finally:
                    pass

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        elif self.mode == "disconnect":
            async def disconnect_generator():
                try:
                    yield b"data: chunk1\n\n"
                    # Keep yielding until client disconnects
                    while True:
                        await asyncio.sleep(0.05)
                        self.keepalive_count += 1
                        yield b"data: keepalive\n\n"
                except (asyncio.CancelledError, GeneratorExit):
                    self.upstream_disconnected.set()
                    raise
                finally:
                    self.upstream_disconnected.set()

            return StreamingResponse(
                disconnect_generator(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache"},
            )

        # Default JSON-RPC response
        return JSONResponse(
            {"jsonrpc": "2.0", "id": 1, "result": {"status": "ok"}},
            headers={"Mcp-Session-Id": "upstream_sess_1"},
        )


class TestOAuthProxyStreaming(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        pass

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "stream_test.db")
        self.store = OAuthStore(self.db_path)

        # 1. Start Fake Upstream on loopback port 0
        self.upstream = StreamingFakeUpstream()
        self.upstream_app = Starlette()
        self.upstream_app.add_route("/mcp", self.upstream.handle_mcp, methods=["POST", "GET", "DELETE"])

        u_cfg = uvicorn.Config(self.upstream_app, host="127.0.0.1", port=0, log_level="error")
        self.u_server = uvicorn.Server(u_cfg)
        self.u_thread = threading.Thread(target=self.u_server.run, daemon=True)
        self.u_thread.start()

        start_deadline = time.time() + 10.0
        while not self.u_server.started:
            if time.time() > start_deadline:
                raise TimeoutError("Fake upstream uvicorn server failed to start within 10s")
            time.sleep(0.01)

        self.u_port = self.u_server.servers[0].sockets[0].getsockname()[1]

        # 2. Setup Config & App pointing to fake upstream
        self.config = Config.from_env({
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{self.u_port}/mcp",
            "MINDHUB_UPSTREAM_API_KEY": "secret-upstream-key",
            "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
            "FACADE_MAX_SCOPE": "mindhub:read mindhub:write",
            "FACADE_DEFAULT_SCOPE": "mindhub:read",
            "FACADE_DB_PATH": self.db_path,
        })

        # Register clients & tokens
        self.client_id = "test_streaming_client"
        self.store.create_client(
            client_id=self.client_id,
            client_name="Streaming Test App",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        self.token_read = "tok_stream_read"
        self.store.create_token(
            token=self.token_read,
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read",
            resource=self.config.resource,
            family_id="fam_stream_1",
            ttl_seconds=3600,
        )
        self.token_write = "tok_stream_write"
        self.store.create_token(
            token=self.token_write,
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read mindhub:write",
            resource=self.config.resource,
            family_id="fam_stream_2",
            ttl_seconds=3600,
        )

        self.facade_app = create_app(self.config, store=self.store)

        # 3. Start Facade on loopback port 0
        f_cfg = uvicorn.Config(self.facade_app, host="127.0.0.1", port=0, log_level="error")
        self.f_server = uvicorn.Server(f_cfg)
        self.f_thread = threading.Thread(target=self.f_server.run, daemon=True)
        self.f_thread.start()

        start_deadline = time.time() + 10.0
        while not self.f_server.started:
            if time.time() > start_deadline:
                raise TimeoutError("Facade uvicorn server failed to start within 10s")
            time.sleep(0.01)

        self.f_port = self.f_server.servers[0].sockets[0].getsockname()[1]
        self.facade_base_url = f"http://127.0.0.1:{self.f_port}"

    def tearDown(self) -> None:
        self.store.close()
        self.u_server.should_exit = True
        self.f_server.should_exit = True
        self.u_thread.join(timeout=5.0)
        self.f_thread.join(timeout=5.0)
        self.temp_dir.cleanup()

    def test_sse_incremental_delivery_no_buffering(self) -> None:
        """Verify chunk 1 is delivered to client before chunk 2 is sent by upstream."""
        self.upstream.mode = "stream"

        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                req = client.build_request(
                    "POST",
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                resp = await client.send(req, stream=True)
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers.get("x-accel-buffering"), "no")

                chunk1_seen = False
                chunk2_seen = False

                async for chunk in resp.aiter_bytes():
                    if b"chunk1" in chunk:
                        chunk1_seen = True
                        # Chunk 1 arrived! Now unblock upstream to send chunk 2
                        self.upstream.chunk1_received.set()
                    elif b"chunk2" in chunk:
                        chunk2_seen = True
                        break

                self.assertTrue(chunk1_seen)
                self.assertTrue(self.upstream.chunk1_received.is_set())
                self.assertTrue(chunk2_seen)
                await resp.aclose()

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_client_disconnect_tears_down_upstream_connection(self) -> None:
        """Verify closing client connection cancels upstream generator."""
        self.upstream.mode = "disconnect"

        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                req = client.build_request(
                    "POST",
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                resp = await client.send(req, stream=True)
                self.assertEqual(resp.status_code, 200)

                # Read chunk 1
                async for chunk in resp.aiter_bytes():
                    if b"chunk1" in chunk:
                        break

                # Disconnect client while upstream is waiting/streaming
                await resp.aclose()

            # Wait for upstream to detect disconnect and set its event
            detected = await asyncio.to_thread(self.upstream.upstream_disconnected.wait, 5.0)
            self.assertTrue(detected, "Upstream did not detect client disconnection within 5s")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_duplicate_keys_in_json_rpc_rejected(self) -> None:
        """Verify JSON with duplicate keys returns 400 and is never forwarded."""
        async def run():
            raw_dup = b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}'
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {self.token_read}",
                        "Content-Type": "application/json",
                    },
                    content=raw_dup,
                )
                self.assertEqual(res.status_code, 400)
                data = res.json()
                self.assertEqual(data.get("error", {}).get("code"), -32700)
                # Upstream never received anything
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_smuggling_utf8_bom_rejected(self) -> None:
        """Verify UTF-8 BOM is rejected with 400 and never forwarded."""
        async def run():
            raw_bom = b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"ping"}'
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {self.token_read}",
                        "Content-Type": "application/json",
                    },
                    content=raw_bom,
                )
                self.assertEqual(res.status_code, 400)
                data = res.json()
                self.assertEqual(data.get("error", {}).get("code"), -32700)
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_smuggling_deep_nesting_depth_rejected(self) -> None:
        """Verify payload with depth > 32 is rejected with 400."""
        async def run():
            curr: dict = {"leaf": 1}
            for _ in range(35):
                curr = {"nest": curr}
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": curr}).encode()

            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {self.token_read}",
                        "Content-Type": "application/json",
                    },
                    content=payload,
                )
                self.assertEqual(res.status_code, 400)
                data = res.json()
                self.assertEqual(data.get("error", {}).get("code"), -32700)
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_reserialized_canonical_json_forwarded_upstream(self) -> None:
        """Verify non-canonical whitespace JSON is forwarded as compact canonical JSON."""
        async def run():
            raw_json = b'{\n  "jsonrpc" :  "2.0" ,\n  "id" : 100 ,\n  "method" : "ping"\n}'
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {self.token_read}",
                        "Content-Type": "application/json",
                    },
                    content=raw_json,
                )
                self.assertEqual(res.status_code, 200)
                # Upstream received canonical compact bytes:
                expected = b'{"jsonrpc":"2.0","id":100,"method":"ping"}'
                self.assertEqual(self.upstream.last_body, expected)
                # Internal API key injected:
                self.assertEqual(self.upstream.last_headers.get("x-api-key"), "secret-upstream-key")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_non_allowlisted_methods_return_32601(self) -> None:
        """Verify non-allowlisted methods return JSON-RPC -32601 without reaching upstream."""
        methods = [
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "tasks/create",
            "tasks/get",
            "completion/complete",
            "logging/setLevel",
        ]

        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                for idx, m in enumerate(methods, start=50):
                    self.upstream.last_body = b""
                    res = await client.post(
                        f"{self.facade_base_url}/mcp",
                        headers={"Authorization": f"Bearer {self.token_read}"},
                        json={"jsonrpc": "2.0", "id": idx, "method": m},
                    )
                    self.assertEqual(res.status_code, 200)
                    data = res.json()
                    self.assertEqual(data.get("id"), idx)
                    self.assertEqual(data.get("error", {}).get("code"), -32601)
                    self.assertIn("Method not found", data.get("error", {}).get("message", ""))
                    # Never forwarded upstream
                    self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_non_allowlisted_notifications_return_202_and_not_forwarded(self) -> None:
        """Verify non-allowlisted notifications return 202 without reaching upstream."""
        notifs = [
            "notifications/progress",
            "notifications/message",
            "tasks/notify",
        ]

        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                for m in notifs:
                    self.upstream.last_body = b""
                    res = await client.post(
                        f"{self.facade_base_url}/mcp",
                        headers={"Authorization": f"Bearer {self.token_read}"},
                        json={"jsonrpc": "2.0", "method": m},
                    )
                    self.assertEqual(res.status_code, 202)
                    self.assertEqual(res.text, "")
                    # Never forwarded upstream
                    self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_lone_surrogates_and_escapes_forwarded_as_pure_ascii(self) -> None:
        """Verify lone surrogates and non-BMP characters are re-serialized as pure ASCII JSON."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Lone surrogate in string value
                self.upstream.last_body = b""
                raw1 = br'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"val": "\ud800"}}'
                res1 = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
                    content=raw1,
                )
                self.assertEqual(res1.status_code, 200)
                self.assertTrue(self.upstream.last_body.isascii())
                self.assertIn(b'"\\ud800"', self.upstream.last_body)

                # 2. Lone surrogate in key
                self.upstream.last_body = b""
                raw2 = br'{"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"\ud800": "val"}}'
                res2 = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
                    content=raw2,
                )
                self.assertEqual(res2.status_code, 200)
                self.assertTrue(self.upstream.last_body.isascii())

                # 3. Non-BMP emoji character (\ud83d\ude00)
                self.upstream.last_body = b""
                raw3 = br'{"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {"emoji": "\ud83d\ude00"}}'
                res3 = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
                    content=raw3,
                )
                self.assertEqual(res3.status_code, 200)
                self.assertTrue(self.upstream.last_body.isascii())
                self.assertIn(b'"\\ud83d\\ude00"', self.upstream.last_body)

                # 4. Escaped params.name: \u0073earch_memory -> normalized after parsing to search_memory
                self.upstream.last_body = b""
                raw4 = br'{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "\u0073earch_memory"}}'
                res4 = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
                    content=raw4,
                )
                self.assertEqual(res4.status_code, 200)
                parsed = json.loads(self.upstream.last_body.decode("ascii"))
                self.assertEqual(parsed["params"]["name"], "search_memory")

                # 5. Lone surrogate in params.name: search_memory\ud800 -> denied after parsing
                self.upstream.last_body = b""
                raw5 = br'{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "search_memory\ud800"}}'
                res5 = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}", "Content-Type": "application/json"},
                    content=raw5,
                )
                self.assertEqual(res5.status_code, 200)
                self.assertEqual(res5.json().get("error", {}).get("code"), -32001)
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_read_only_token_calling_remember_returns_32001(self) -> None:
        """Verify read token calling remember is denied with -32001 without reaching upstream."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "tools/call",
                        "params": {"name": "remember", "arguments": {"content": "test"}},
                    },
                )
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertEqual(data.get("id"), 99)
                self.assertEqual(data.get("error", {}).get("code"), -32001)
                self.assertIn("not permitted", data.get("error", {}).get("message", ""))
                # Never forwarded upstream
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_read_only_token_calling_search_memory_forwarded(self) -> None:
        """Verify read token calling search_memory is allowed and forwarded upstream."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={"Authorization": f"Bearer {self.token_read}"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 101,
                        "method": "tools/call",
                        "params": {"name": "search_memory", "arguments": {"query": "test"}},
                    },
                )
                self.assertEqual(res.status_code, 200)
                # Forwarded upstream
                parsed = json.loads(self.upstream.last_body.decode())
                self.assertEqual(parsed.get("method"), "tools/call")
                self.assertEqual(parsed.get("params", {}).get("name"), "search_memory")
                self.assertEqual(self.upstream.last_headers.get("x-api-key"), "secret-upstream-key")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_p3_chunked_post_without_content_length_exceeding_1mib_returns_413(self) -> None:
        """Verify chunked POST without Content-Length exceeding 1 MiB returns 413 on real socket path."""
        async def run():
            chunk_size = 64 * 1024  # 64 KiB
            num_chunks = 17  # 17 * 64 KiB = 1088 KiB > 1024 KiB (1 MiB)

            async def chunk_generator():
                for _ in range(num_chunks):
                    yield b"a" * chunk_size

            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/mcp",
                    content=chunk_generator(),
                    headers={
                        "Authorization": f"Bearer {self.token_read}",
                        "Content-Type": "application/json",
                    },
                )
                self.assertEqual(res.status_code, 413)
                data = res.json()
                self.assertEqual(data.get("error"), "payload_too_large")
                self.assertEqual(self.upstream.last_body, b"")

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r2_chunked_body_above_cap_without_content_length_returns_413(self) -> None:
        """Verify chunked body above cap without Content-Length returns 413 for unauthenticated endpoints."""
        async def run():
            async def chunk_gen(total_kib: int):
                for _ in range(total_kib):
                    yield b"x" * 1024

            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. /register cap is 8 KiB -> send 9 KiB
                r_reg = await client.post(
                    f"{self.facade_base_url}/register",
                    content=chunk_gen(9),
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(r_reg.status_code, 413)

                # 2. /token cap is 16 KiB -> send 17 KiB
                r_tok = await client.post(
                    f"{self.facade_base_url}/token",
                    content=chunk_gen(17),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(r_tok.status_code, 413)

                # 3. /revoke cap is 16 KiB -> send 17 KiB
                r_rev = await client.post(
                    f"{self.facade_base_url}/revoke",
                    content=chunk_gen(17),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(r_rev.status_code, 413)

                # 4. /authorize/decision cap is 16 KiB -> send 17 KiB
                r_dec = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    content=chunk_gen(17),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(r_dec.status_code, 413)

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r2_multipart_to_authorize_decision_returns_400(self) -> None:
        async def run():
            multipart_body = (
                b"--boundary123\r\n"
                b"Content-Disposition: form-data; name=\"action\"\r\n\r\n"
                b"allow\r\n"
                b"--boundary123--\r\n"
            )
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    content=multipart_body,
                    headers={"Content-Type": "multipart/form-data; boundary=boundary123"},
                )
                self.assertEqual(res.status_code, 400)

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r2_duplicate_parameters_rejected_and_repeated_resource_accepted(self) -> None:
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Duplicate client_id in GET /authorize -> 400
                r_dup_cid = await client.get(
                    f"{self.facade_base_url}/authorize?client_id=c1&client_id=c2"
                )
                self.assertEqual(r_dup_cid.status_code, 400)

                # 2. Duplicate redirect_uri in GET /authorize -> 400
                r_dup_red = await client.get(
                    f"{self.facade_base_url}/authorize?client_id={self.client_id}&redirect_uri=r1&redirect_uri=r2"
                )
                self.assertEqual(r_dup_red.status_code, 400)

                # 3. Duplicate grant_type in POST /token -> 400
                r_dup_gt = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    content=b"grant_type=authorization_code&grant_type=refresh_token&client_id=c1",
                )
                self.assertEqual(r_dup_gt.status_code, 400)

                # 4. Repeated identical resource accepted in GET /authorize
                res_url = self.config.resource
                r_rep_res = await client.get(
                    f"{self.facade_base_url}/authorize"
                    f"?client_id={self.client_id}"
                    f"&redirect_uri=https://claude.ai/api/mcp/auth_callback"
                    f"&response_type=code"
                    f"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                    f"&code_challenge_method=S256"
                    f"&resource={res_url}&resource={res_url}"
                )
                self.assertEqual(r_rep_res.status_code, 200)

                # 5. F2: 10 KiB parameter name duplicated -> 400 and error description length is bounded
                large_param = "a" * 10240
                r_large = await client.get(
                    f"{self.facade_base_url}/authorize?{large_param}=1&{large_param}=2"
                )
                self.assertEqual(r_large.status_code, 400)
                self.assertIn("Duplicate query parameter: " + "a" * 64, r_large.text)
                self.assertNotIn("a" * 65, r_large.text)

                # Non-printable chars replaced with ? and length bounded
                non_print_param = "bad\x01\x1f\x7f\xffparam_" + ("x" * 100)
                r_tok = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    content=f"{non_print_param}=1&{non_print_param}=2".encode("utf-8"),
                )
                self.assertEqual(r_tok.status_code, 400)
                tok_desc = r_tok.json().get("error_description", "")
                self.assertLessEqual(len(tok_desc), 128)
                self.assertIn("?", tok_desc)
                self.assertNotIn("x" * 65, tok_desc)

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r8_a_upstream_resets_connection_before_response_returns_502(self) -> None:
        async def run():
            async def reset_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await reader.read(1024)
                writer.close()
                await writer.wait_closed()

            srv = await asyncio.start_server(reset_handler, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]

            temp_dir = tempfile.TemporaryDirectory()
            db_path = os.path.join(temp_dir.name, "r8_a.db")
            st = OAuthStore(db_path)
            st.create_client("c1", "Client 1", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code"])
            cfg = Config.from_env({
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{port}/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_DB_PATH": db_path,
            })
            st.create_token("tok_r8_a", "access", "c1", "mindhub:read", cfg.resource, "fam_r8_a", 3600)
            app = create_app(cfg, store=st)

            u_cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
            u_srv = uvicorn.Server(u_cfg)
            t = threading.Thread(target=u_srv.run, daemon=True)
            t.start()
            while not u_srv.started:
                await asyncio.sleep(0.01)
            f_port = u_srv.servers[0].sockets[0].getsockname()[1]

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.post(
                        f"http://127.0.0.1:{f_port}/mcp",
                        headers={"Authorization": "Bearer tok_r8_a", "Content-Type": "application/json"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    )
                    self.assertEqual(res.status_code, 502)
            finally:
                u_srv.should_exit = True
                srv.close()
                await srv.wait_closed()
                st.close()

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r8_b_upstream_sends_garbage_returns_502(self) -> None:
        async def run():
            async def garbage_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await reader.read(1024)
                writer.write(b"NOT HTTP GARBAGE\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            srv = await asyncio.start_server(garbage_handler, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]

            temp_dir = tempfile.TemporaryDirectory()
            db_path = os.path.join(temp_dir.name, "r8_b.db")
            st = OAuthStore(db_path)
            st.create_client("c1", "Client 1", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code"])
            cfg = Config.from_env({
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{port}/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_DB_PATH": db_path,
            })
            st.create_token("tok_r8_b", "access", "c1", "mindhub:read", cfg.resource, "fam_r8_b", 3600)
            app = create_app(cfg, store=st)

            u_cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
            u_srv = uvicorn.Server(u_cfg)
            t = threading.Thread(target=u_srv.run, daemon=True)
            t.start()
            while not u_srv.started:
                await asyncio.sleep(0.01)
            f_port = u_srv.servers[0].sockets[0].getsockname()[1]

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.post(
                        f"http://127.0.0.1:{f_port}/mcp",
                        headers={"Authorization": "Bearer tok_r8_b", "Content-Type": "application/json"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    )
                    self.assertEqual(res.status_code, 502)
            finally:
                u_srv.should_exit = True
                srv.close()
                await srv.wait_closed()
                st.close()

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r8_c_upstream_premature_close_before_content_length_aborts(self) -> None:
        async def run():
            async def trunc_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await reader.read(1024)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"status\":\"incomp")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            srv = await asyncio.start_server(trunc_handler, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]

            temp_dir = tempfile.TemporaryDirectory()
            db_path = os.path.join(temp_dir.name, "r8_c.db")
            st = OAuthStore(db_path)
            st.create_client("c1", "Client 1", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code"])
            cfg = Config.from_env({
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{port}/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_DB_PATH": db_path,
            })
            st.create_token("tok_r8_c", "access", "c1", "mindhub:read", cfg.resource, "fam_r8_c", 3600)
            app = create_app(cfg, store=st)

            u_cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
            u_srv = uvicorn.Server(u_cfg)
            t = threading.Thread(target=u_srv.run, daemon=True)
            t.start()
            while not u_srv.started:
                await asyncio.sleep(0.01)
            f_port = u_srv.servers[0].sockets[0].getsockname()[1]

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    with self.assertRaises((httpx.TransportError, httpx.HTTPError)):
                        await client.post(
                            f"http://127.0.0.1:{f_port}/mcp",
                            headers={"Authorization": "Bearer tok_r8_c", "Content-Type": "application/json"},
                            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        )
            finally:
                u_srv.should_exit = True
                srv.close()
                await srv.wait_closed()
                st.close()

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))

    def test_r8_d_upstream_sse_stalls_past_read_timeout_ends_cleanly(self) -> None:
        async def run():
            async def sse_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await reader.read(1024)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\ndata: event1\n\n")
                await writer.drain()
                await asyncio.sleep(1.0)
                writer.close()
                await writer.wait_closed()

            srv = await asyncio.start_server(sse_handler, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]

            temp_dir = tempfile.TemporaryDirectory()
            db_path = os.path.join(temp_dir.name, "r8_d.db")
            st = OAuthStore(db_path)
            st.create_client("c1", "Client 1", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code"])
            cfg = Config.from_env({
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{port}/mcp",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": hash_password("correct-horse-battery-staple-long"),
                "FACADE_DB_PATH": db_path,
            })
            st.create_token("tok_r8_d", "access", "c1", "mindhub:read", cfg.resource, "fam_r8_d", 3600)
            fast_client = httpx.AsyncClient(timeout=httpx.Timeout(read=0.2, connect=5.0, write=5.0, pool=5.0))
            app = create_app(cfg, store=st, http_client=fast_client)

            u_cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
            u_srv = uvicorn.Server(u_cfg)
            t = threading.Thread(target=u_srv.run, daemon=True)
            t.start()
            while not u_srv.started:
                await asyncio.sleep(0.01)
            f_port = u_srv.servers[0].sockets[0].getsockname()[1]

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.post(
                        f"http://127.0.0.1:{f_port}/mcp",
                        headers={"Authorization": "Bearer tok_r8_d", "Content-Type": "application/json"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    )
                    self.assertEqual(res.status_code, 200)
                    self.assertIn(b"data: event1\n\n", res.content)
            finally:
                u_srv.should_exit = True
                srv.close()
                await srv.wait_closed()
                st.close()

        asyncio.run(asyncio.wait_for(run(), timeout=10.0))


if __name__ == "__main__":
    unittest.main()
