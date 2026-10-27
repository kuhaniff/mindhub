"""Tests for HTTP client compatibility module."""
from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest
from typing import AsyncIterator

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route
import uvicorn

from mindhub_oauth._http import httpx


async def json_endpoint(request):
    return JSONResponse({"status": "ok"}, headers={"x-custom-header": "mindhub"})


async def asgi_stream_endpoint(request):
    async def gen() -> AsyncIterator[bytes]:
        yield b"data: chunk-a\n\n"
        yield b"data: chunk-b\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


class TestHttpClientASGITransport(unittest.IsolatedAsyncioTestCase):
    """Test AsyncClient + ASGITransport for status, headers, and simple stream."""

    async def test_async_client_and_asgi_transport(self) -> None:
        self.assertTrue(hasattr(httpx, "AsyncClient"))
        self.assertTrue(hasattr(httpx, "ASGITransport"))

        app = Starlette(
            routes=[
                Route("/json", json_endpoint),
                Route("/stream", asgi_stream_endpoint),
            ]
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            # Test status and headers
            res = await client.get("/json")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.headers.get("x-custom-header"), "mindhub")
            self.assertEqual(res.json(), {"status": "ok"})

            # Test streaming response
            chunks: list[bytes] = []
            async with client.stream("GET", "/stream") as stream_res:
                self.assertEqual(stream_res.status_code, 200)
                self.assertIn("text/event-stream", stream_res.headers.get("content-type", ""))
                async for chunk in stream_res.aiter_bytes():
                    chunks.append(chunk)

            full_payload = b"".join(chunks)
            self.assertIn(b"chunk-a", full_payload)
            self.assertIn(b"chunk-b", full_payload)


class TestHttpClientLoopbackIncrementalStreaming(unittest.IsolatedAsyncioTestCase):
    """Real loopback socket smoke test proving incremental SSE chunk delivery."""

    @classmethod
    def setUpClass(cls) -> None:
        # Check if binding loopback socket is permitted
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.bind(("127.0.0.1", 0))
            test_sock.close()
        except Exception as exc:
            raise unittest.SkipTest(f"LOUD SKIP: Cannot bind loopback socket in this environment: {exc}")

        cls.client_received_first_chunk = threading.Event()

        async def sse_app(scope, receive, send):
            if scope["type"] == "http":
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"text/event-stream"),
                            (b"cache-control", b"no-cache"),
                        ],
                    }
                )
                # Send first chunk
                await send({"type": "http.response.body", "body": b"event: 1\ndata: first\n\n", "more_body": True})

                # Wait deterministically for test client to receive first chunk
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, cls.client_received_first_chunk.wait, 10.0)

                # Send second chunk and finish
                await send({"type": "http.response.body", "body": b"event: 2\ndata: second\n\n", "more_body": False})

        config = uvicorn.Config(app=sse_app, host="127.0.0.1", port=0, log_level="error", lifespan="off")
        cls.server = uvicorn.Server(config=config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()

        # Wait for server to start with a timeout
        start_wait = time.monotonic()
        while not cls.server.started:
            if time.monotonic() - start_wait > 5.0:
                cls.server.should_exit = True
                cls.thread.join(timeout=2.0)
                raise RuntimeError("Uvicorn test server failed to start within 5s")
            time.sleep(0.01)

        cls.port = cls.server.servers[0].sockets[0].getsockname()[1]

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "server"):
            cls.server.should_exit = True
            cls.thread.join(timeout=5.0)

    async def test_incremental_sse_chunk_delivery_over_loopback(self) -> None:
        url = f"http://127.0.0.1:{self.port}"
        received_chunks: list[bytes] = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            async with client.stream("GET", url) as resp:
                self.assertEqual(resp.status_code, 200)

                stream_iter = resp.aiter_bytes()

                # Await first chunk with hard timeout
                chunk1 = await asyncio.wait_for(stream_iter.__anext__(), timeout=5.0)
                received_chunks.append(chunk1)
                self.assertIn(b"first", chunk1)

                # Signal server to proceed to second chunk
                self.client_received_first_chunk.set()

                # Await second chunk with hard timeout
                chunk2 = await asyncio.wait_for(stream_iter.__anext__(), timeout=5.0)
                received_chunks.append(chunk2)
                self.assertIn(b"second", chunk2)

        self.assertEqual(len(received_chunks), 2)


if __name__ == "__main__":
    unittest.main()
