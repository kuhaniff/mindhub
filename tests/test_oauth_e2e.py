"""End-to-end integration tests for Mindhub OAuth Facade (Milestone M5).

Tests real sockets via threaded uvicorn on 127.0.0.1:0 for BOTH the real
Mindhub create_app(...) with a temporary SQLite DB and random API key, and
the facade pointing at it.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.parse
from typing import Any

import uvicorn

from mindhub_oauth._http import httpx
from mindhub_oauth.app import create_app as create_facade_app
from mindhub_oauth.config import Config
from mindhub_oauth.security import hash_password
from mindhub_oauth.store import OAuthStore
from mindhub.server import create_app as create_mindhub_app
from mindhub.sqlite_memory import SQLiteMemoryPersistence
from mindhub.sqlite_project_state import SQLiteProjectStatePersistence


def parse_mcp_response(res: httpx.Response) -> dict[str, Any]:
    """Extract JSON payload from either application/json or text/event-stream response."""
    text = res.text
    if "data: " in text:
        for line in text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[6:])
    return res.json()


class RecordingASGIWrapper:
    """ASGI middleware that records incoming HTTP request headers on the Mindhub app."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.recorded_requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers: dict[str, str] = {}
            for k, v in scope.get("headers", []):
                key = k.decode("latin1").lower()
                val = v.decode("latin1")
                headers[key] = val
            with self._lock:
                self.recorded_requests.append({
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "headers": headers,
                })
        await self.app(scope, receive, send)


class MemoryLogCaptureHandler(logging.Handler):
    """Log handler capturing all log lines in memory for secret hygiene validation."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []
        self.formatted_lines: list[str] = []
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            with self._lock:
                self.records.append(record)
                self.formatted_lines.append(msg)
        except Exception:
            pass

    def get_all_text(self) -> str:
        with self._lock:
            return "\n".join(self.formatted_lines)


class TestOAuthE2E(unittest.TestCase):
    """M5 End-to-end integration tests using real loopback sockets."""

    temp_dir: tempfile.TemporaryDirectory
    mindhub_db_path: str
    facade_db_path: str
    upstream_api_key: str
    owner_password: str
    owner_password_hash: str
    store: OAuthStore
    config: Config

    mindhub_server: uvicorn.Server
    mindhub_thread: threading.Thread
    mindhub_port: int
    recording_wrapper: RecordingASGIWrapper

    facade_server: uvicorn.Server
    facade_thread: threading.Thread
    facade_port: int
    facade_base_url: str

    log_handler: MemoryLogCaptureHandler
    secrets_to_check: set[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.mindhub_db_path = os.path.join(cls.temp_dir.name, "mindhub_e2e.db")
        cls.facade_db_path = os.path.join(cls.temp_dir.name, "facade_e2e.db")

        cls.upstream_api_key = f"key_{secrets.token_hex(16)}"
        cls.owner_password = f"pw_{secrets.token_urlsafe(32)}"
        cls.owner_password_hash = hash_password(cls.owner_password)
        cls.secrets_to_check = {cls.upstream_api_key, cls.owner_password}

        # Setup root log capture (silence client transport trace logs)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpcore2").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpx2").setLevel(logging.WARNING)
        cls.log_handler = MemoryLogCaptureHandler()
        cls.log_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(cls.log_handler)
        logging.getLogger().setLevel(logging.INFO)

        # 1. Start real Mindhub app with SQLite persistence
        cls.mem_backend = SQLiteMemoryPersistence(cls.mindhub_db_path)
        cls.state_backend = SQLiteProjectStatePersistence(cls.mindhub_db_path)
        os.environ["MINDHUB_API_KEYS"] = cls.upstream_api_key
        raw_mindhub_app = create_mindhub_app(memory_backend=cls.mem_backend, state_backend=cls.state_backend)
        cls.recording_wrapper = RecordingASGIWrapper(raw_mindhub_app)

        m_cfg = uvicorn.Config(cls.recording_wrapper, host="127.0.0.1", port=0, log_level="error")
        cls.mindhub_server = uvicorn.Server(m_cfg)
        cls.mindhub_thread = threading.Thread(target=cls.mindhub_server.run, daemon=True)
        cls.mindhub_thread.start()

        deadline = time.time() + 10.0
        while not cls.mindhub_server.started:
            if time.time() > deadline:
                raise TimeoutError("Mindhub server failed to start within 10s")
            time.sleep(0.01)
        cls.mindhub_port = cls.mindhub_server.servers[0].sockets[0].getsockname()[1]

        # 2. Setup Facade
        cls.store = OAuthStore(cls.facade_db_path)
        cls.config = Config.from_env({
            "FACADE_PUBLIC_URL": "https://mindhub.example.com",
            "FACADE_UPSTREAM_URL": f"http://127.0.0.1:{cls.mindhub_port}/mcp",
            "MINDHUB_UPSTREAM_API_KEY": cls.upstream_api_key,
            "FACADE_OWNER_PASSWORD_HASH": cls.owner_password_hash,
            "FACADE_MAX_SCOPE": "mindhub:read mindhub:write",
            "FACADE_DEFAULT_SCOPE": "mindhub:read",
            "FACADE_DB_PATH": cls.facade_db_path,
        })
        facade_app = create_facade_app(cls.config, store=cls.store)

        f_cfg = uvicorn.Config(facade_app, host="127.0.0.1", port=0, log_level="error")
        cls.facade_server = uvicorn.Server(f_cfg)
        cls.facade_thread = threading.Thread(target=cls.facade_server.run, daemon=True)
        cls.facade_thread.start()

        deadline = time.time() + 10.0
        while not cls.facade_server.started:
            if time.time() > deadline:
                raise TimeoutError("Facade server failed to start within 10s")
            time.sleep(0.01)
        cls.facade_port = cls.facade_server.servers[0].sockets[0].getsockname()[1]
        cls.facade_base_url = f"http://127.0.0.1:{cls.facade_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.store.close()
        cls.mem_backend.close()
        cls.state_backend.close()
        cls.mindhub_server.should_exit = True
        cls.facade_server.should_exit = True
        cls.mindhub_thread.join(timeout=5.0)
        cls.facade_thread.join(timeout=5.0)
        logging.getLogger().removeHandler(cls.log_handler)
        cls.temp_dir.cleanup()

    def test_e1_claude_scripted_oauth_flow(self) -> None:
        """E1: Full scripted OAuth client flow (Claude-style) with real Mindhub upstream."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Unauthenticated POST /mcp -> 401 with WWW-Authenticate containing resource_metadata
                r_unauth = await client.post(f"{self.facade_base_url}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                self.assertEqual(r_unauth.status_code, 401)
                www_auth = r_unauth.headers.get("www-authenticate", "")
                self.assertIn("Bearer", www_auth)
                self.assertIn('resource_metadata="', www_auth)

                # Extract PRM URL
                match_prm = re.search(r'resource_metadata="([^"]+)"', www_auth)
                self.assertIsNotNone(match_prm)
                prm_url_str = match_prm.group(1)
                self.assertEqual(prm_url_str, f"{self.config.issuer}/.well-known/oauth-protected-resource")

                # 2. Fetch Protected Resource Metadata (PRM)
                r_prm = await client.get(f"{self.facade_base_url}/.well-known/oauth-protected-resource")
                self.assertEqual(r_prm.status_code, 200)
                prm_data = r_prm.json()
                self.assertEqual(prm_data.get("resource"), self.config.resource)
                self.assertEqual(prm_data.get("authorization_servers"), [self.config.public_url])

                # 3. Fetch Authorization Server (AS) Metadata
                r_as = await client.get(f"{self.facade_base_url}/.well-known/oauth-authorization-server")
                self.assertEqual(r_as.status_code, 200)
                as_data = r_as.json()
                self.assertEqual(as_data.get("issuer"), self.config.public_url)
                self.assertEqual(as_data.get("authorization_endpoint"), f"{self.config.public_url}/authorize")
                self.assertEqual(as_data.get("token_endpoint"), f"{self.config.public_url}/token")
                self.assertEqual(as_data.get("registration_endpoint"), f"{self.config.public_url}/register")
                self.assertEqual(as_data.get("revocation_endpoint"), f"{self.config.public_url}/revoke")
                self.assertIn("S256", as_data.get("code_challenge_methods_supported", []))
                self.assertIn("authorization_code", as_data.get("grant_types_supported", []))
                self.assertIn("refresh_token", as_data.get("grant_types_supported", []))

                # 4. POST /register (Claude callback URI)
                claude_redirect = "https://claude.ai/api/mcp/auth_callback"
                r_reg = await client.post(
                    f"{self.facade_base_url}/register",
                    json={
                        "client_name": "Claude Desktop / Web",
                        "redirect_uris": [claude_redirect],
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "none",
                    },
                )
                self.assertEqual(r_reg.status_code, 201)
                reg_data = r_reg.json()
                client_id = reg_data["client_id"]
                self.assertIsNotNone(client_id)

                # 5. GET /authorize (parse request_id/csrf hidden fields and mh_csrf cookie)
                code_verifier = secrets.token_urlsafe(48)
                self.secrets_to_check.add(code_verifier)
                digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
                code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
                state = secrets.token_urlsafe(16)

                r_auth = await client.get(
                    f"{self.facade_base_url}/authorize",
                    params={
                        "client_id": client_id,
                        "redirect_uri": claude_redirect,
                        "response_type": "code",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "state": state,
                        "scope": "mindhub:read",
                        "resource": self.config.resource,
                    },
                )
                self.assertEqual(r_auth.status_code, 200)
                html_text = r_auth.text
                req_match = re.search(r'name="request_id" value="([^"]+)"', html_text)
                csrf_match = re.search(r'name="csrf" value="([^"]+)"', html_text)
                self.assertIsNotNone(req_match)
                self.assertIsNotNone(csrf_match)
                request_id = req_match.group(1)
                csrf_val = csrf_match.group(1)
                mh_csrf_cookie = r_auth.cookies.get("mh_csrf")
                self.assertIsNotNone(mh_csrf_cookie)
                self.secrets_to_check.add(request_id)
                self.secrets_to_check.add(csrf_val)

                # 6. POST /authorize/decision with a WRONG password (expect 401, lockout counter incremented)
                r_dec_wrong = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": f"mh_csrf={mh_csrf_cookie}",
                    },
                    data={
                        "request_id": request_id,
                        "csrf": csrf_val,
                        "password": "wrong-password-attempt",
                        "action": "allow",
                        "scope_choice": "read",
                    },
                )
                self.assertEqual(r_dec_wrong.status_code, 401)
                # Verify audit logged failed login
                audit_events = self.store.get_audit_events()
                self.assertTrue(any(ev.event == "login_failed" for ev in audit_events))

                # 7. POST /authorize/decision with the CORRECT password (Location has code, state, iss)
                r_dec_ok = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": f"mh_csrf={mh_csrf_cookie}",
                    },
                    data={
                        "request_id": request_id,
                        "csrf": csrf_val,
                        "password": self.owner_password,
                        "action": "allow",
                        "scope_choice": "read",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(r_dec_ok.status_code, 302)
                loc = r_dec_ok.headers.get("location", "")
                self.assertTrue(loc.startswith(claude_redirect))
                parsed_loc = urllib.parse.urlsplit(loc)
                qs = urllib.parse.parse_qs(parsed_loc.query)
                self.assertIn("code", qs)
                self.assertEqual(qs.get("state"), [state])
                self.assertEqual(qs.get("iss"), [self.config.issuer])
                auth_code = qs["code"][0]
                self.secrets_to_check.add(auth_code)

                # 8. POST /token (PKCE S256)
                r_tok = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "authorization_code",
                        "code": auth_code,
                        "client_id": client_id,
                        "redirect_uri": claude_redirect,
                        "code_verifier": code_verifier,
                    },
                )
                self.assertEqual(r_tok.status_code, 200)
                tok_data = r_tok.json()
                access_token = tok_data["access_token"]
                refresh_token = tok_data["refresh_token"]
                self.assertEqual(tok_data.get("token_type", "").lower(), "bearer")
                self.assertEqual(tok_data.get("scope"), "mindhub:read")
                self.secrets_to_check.add(access_token)
                self.secrets_to_check.add(refresh_token)

                # 9. MCP initialize (capture Mcp-Session-Id)
                r_init = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "claude-client", "version": "1.0"},
                        },
                    },
                )
                self.assertEqual(r_init.status_code, 200)
                sess_id = r_init.headers.get("mcp-session-id")
                self.assertIsNotNone(sess_id)

                # 10. MCP notifications/initialized
                r_notif = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )
                self.assertIn(r_notif.status_code, (200, 202, 204))

                # 11. MCP tools/list (assert EXACTLY the 5 tools)
                r_tools = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                )
                self.assertEqual(r_tools.status_code, 200)
                tools_payload = parse_mcp_response(r_tools)
                self.assertIn("result", tools_payload)
                tools = tools_payload["result"].get("tools", [])
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

                # 12. tools/call search_memory (permitted under mindhub:read)
                r_search = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "search_memory", "arguments": {"query": "initial"}},
                    },
                )
                self.assertEqual(r_search.status_code, 200)
                search_payload = parse_mcp_response(r_search)
                self.assertIn("result", search_payload)

                # 13. tools/call remember with READ-ONLY token denied with -32001 and DB unchanged
                conn_b = sqlite3.connect(self.mindhub_db_path)
                try:
                    count_before = conn_b.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
                finally:
                    conn_b.close()

                r_rem = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {"name": "remember", "arguments": {"content": "denied marker"}},
                    },
                )
                self.assertEqual(r_rem.status_code, 200)
                rem_payload = parse_mcp_response(r_rem)
                self.assertIn("error", rem_payload)
                self.assertEqual(rem_payload["error"].get("code"), -32001)

                conn_a = sqlite3.connect(self.mindhub_db_path)
                try:
                    count_after = conn_a.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
                finally:
                    conn_a.close()
                self.assertEqual(count_before, count_after)

                # 14. refresh -> returns new access_token and new refresh_token
                r_ref = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": client_id,
                    },
                )
                self.assertEqual(r_ref.status_code, 200)
                ref_payload = r_ref.json()
                new_access_token = ref_payload["access_token"]
                new_refresh_token = ref_payload["refresh_token"]
                self.assertNotEqual(new_access_token, access_token)
                self.assertNotEqual(new_refresh_token, refresh_token)
                self.secrets_to_check.add(new_access_token)
                self.secrets_to_check.add(new_refresh_token)

                # 15. Call again with new access token -> tools/call search_memory succeeds
                r_search_new = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {new_access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {"name": "search_memory", "arguments": {"query": "initial"}},
                    },
                )
                self.assertEqual(r_search_new.status_code, 200)
                self.assertIn("result", parse_mcp_response(r_search_new))

                # 16. Replay OLD refresh token -> family revoked (new access token gets 401)
                r_replay = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": client_id,
                    },
                )
                self.assertEqual(r_replay.status_code, 400)
                self.assertEqual(r_replay.json().get("error"), "invalid_grant")

                # The new access token now gets 401
                r_dead = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {new_access_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {"name": "search_memory", "arguments": {"query": "initial"}},
                    },
                )
                self.assertEqual(r_dead.status_code, 401)

                # 17. /revoke behaviour
                # Issue a fresh token to test revocation
                fresh_token = f"tok_rev_{secrets.token_hex(16)}"
                self.secrets_to_check.add(fresh_token)
                self.store.create_token(
                    token=fresh_token,
                    kind="access",
                    client_id=client_id,
                    scope="mindhub:read",
                    resource=self.config.resource,
                    family_id="fam_e1_rev",
                    ttl_seconds=3600,
                )
                r_rev = await client.post(
                    f"{self.facade_base_url}/revoke",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={"token": fresh_token, "client_id": client_id},
                )
                self.assertEqual(r_rev.status_code, 200)
                # Calling /mcp with revoked token gets 401
                r_rev_check = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {fresh_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "id": 7, "method": "ping"},
                )
                self.assertEqual(r_rev_check.status_code, 401)

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e2_write_path(self) -> None:
        """E2: Write path with scope_choice=readwrite; marker persisted and verified via direct Mindhub call."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                redirect_uri = "https://claude.ai/api/mcp/auth_callback"
                r_reg = await client.post(
                    f"{self.facade_base_url}/register",
                    json={
                        "client_name": "Claude Write Client",
                        "redirect_uris": [redirect_uri],
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "none",
                    },
                )
                client_id = r_reg.json()["client_id"]

                verifier = secrets.token_urlsafe(48)
                self.secrets_to_check.add(verifier)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
                state = secrets.token_urlsafe(16)

                r_auth = await client.get(
                    f"{self.facade_base_url}/authorize",
                    params={
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "response_type": "code",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "state": state,
                        "scope": "mindhub:read mindhub:write",
                        "resource": self.config.resource,
                    },
                )
                self.assertEqual(r_auth.status_code, 200)
                req_id = re.search(r'name="request_id" value="([^"]+)"', r_auth.text).group(1)
                csrf = re.search(r'name="csrf" value="([^"]+)"', r_auth.text).group(1)
                mh_csrf = r_auth.cookies.get("mh_csrf")
                self.secrets_to_check.add(req_id)
                self.secrets_to_check.add(csrf)

                # Consent decision with scope_choice="readwrite"
                r_dec = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": f"mh_csrf={mh_csrf}",
                    },
                    data={
                        "request_id": req_id,
                        "csrf": csrf,
                        "password": self.owner_password,
                        "action": "allow",
                        "scope_choice": "readwrite",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(r_dec.status_code, 302)
                loc = r_dec.headers.get("location", "")
                auth_code = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["code"][0]
                self.secrets_to_check.add(auth_code)

                # Exchange code for write token
                r_tok = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "authorization_code",
                        "code": auth_code,
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "code_verifier": verifier,
                    },
                )
                self.assertEqual(r_tok.status_code, 200)
                tok_data = r_tok.json()
                write_token = tok_data["access_token"]
                self.assertIn("mindhub:write", tok_data.get("scope", ""))
                self.secrets_to_check.add(write_token)

                # Initialize through facade
                r_init = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {write_token}",
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "claude-write", "version": "1.0"},
                        },
                    },
                )
                self.assertEqual(r_init.status_code, 200)
                sess_id = r_init.headers.get("mcp-session-id")

                await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {write_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )

                # Call remember with a unique marker through the facade
                unique_marker = f"e2_marker_{secrets.token_hex(12)}"
                r_rem = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {write_token}",
                        "Mcp-Session-Id": sess_id,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "remember", "arguments": {"content": unique_marker, "memory_type": "fact"}},
                    },
                )
                self.assertEqual(r_rem.status_code, 200)
                rem_data = parse_mcp_response(r_rem)
                self.assertIn("result", rem_data)

                # DIRECT X-API-Key request to Mindhub app (same app, no facade)
                r_direct_init = await client.post(
                    f"http://127.0.0.1:{self.mindhub_port}/mcp",
                    headers={
                        "X-API-Key": self.upstream_api_key,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "direct-client", "version": "1.0"},
                        },
                    },
                )
                self.assertEqual(r_direct_init.status_code, 200)
                direct_sess = r_direct_init.headers.get("mcp-session-id")

                r_direct_search = await client.post(
                    f"http://127.0.0.1:{self.mindhub_port}/mcp",
                    headers={
                        "X-API-Key": self.upstream_api_key,
                        "Mcp-Session-Id": direct_sess,
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "search_memory", "arguments": {"query": unique_marker}},
                    },
                )
                self.assertEqual(r_direct_search.status_code, 200)
                direct_search_data = parse_mcp_response(r_direct_search)
                self.assertIn(unique_marker, json.dumps(direct_search_data))

                # Verify marker exists in SQLite DB directly
                conn_m = sqlite3.connect(self.mindhub_db_path)
                try:
                    rows = conn_m.execute("SELECT content FROM memories WHERE content = ?", (unique_marker,)).fetchall()
                finally:
                    conn_m.close()
                self.assertEqual(len(rows), 1)

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e3_gemini_style(self) -> None:
        """E3: Gemini-style client: DCR with 6 URIs, client_secret_post -> none, 200 meta-refresh without form-action CSP, HEAD /mcp 401."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                google_redirects = [
                    "https://oauth-redirect.googleusercontent.com/r/gemini_1",
                    "https://oauth-redirect.googleusercontent.com/r/gemini_2",
                    "https://oauth-redirect.googleusercontent.com/r/gemini_3",
                    "https://oauth-redirect.googleusercontent.com/a/gemini_4",
                    "https://oauth-redirect-sandbox.googleusercontent.com/r/gemini_5",
                    "https://oauth-redirect-sandbox.googleusercontent.com/a/gemini_6",
                ]
                r_reg = await client.post(
                    f"{self.facade_base_url}/register",
                    json={
                        "client_name": "Google Gemini Connector",
                        "redirect_uris": google_redirects,
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "client_secret_post",
                    },
                )
                self.assertEqual(r_reg.status_code, 201)
                reg_payload = r_reg.json()
                self.assertEqual(reg_payload.get("token_endpoint_auth_method"), "none")
                self.assertNotIn("client_secret", reg_payload)
                self.assertEqual(len(reg_payload.get("redirect_uris", [])), 6)
                client_id = reg_payload["client_id"]

                # Authorize with a Google redirect URI
                target_redirect = google_redirects[0]
                verifier = secrets.token_urlsafe(48)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
                state = secrets.token_urlsafe(16)

                r_auth = await client.get(
                    f"{self.facade_base_url}/authorize",
                    params={
                        "client_id": client_id,
                        "redirect_uri": target_redirect,
                        "response_type": "code",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "state": state,
                        "scope": "mindhub:read",
                    },
                )
                self.assertEqual(r_auth.status_code, 200)
                req_id = re.search(r'name="request_id" value="([^"]+)"', r_auth.text).group(1)
                csrf = re.search(r'name="csrf" value="([^"]+)"', r_auth.text).group(1)
                mh_csrf = r_auth.cookies.get("mh_csrf")

                # Consent decision for Google URI returns 200 meta-refresh page (not a 302)
                r_dec = await client.post(
                    f"{self.facade_base_url}/authorize/decision",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": f"mh_csrf={mh_csrf}",
                    },
                    data={
                        "request_id": req_id,
                        "csrf": csrf,
                        "password": self.owner_password,
                        "action": "allow",
                        "scope_choice": "read",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(r_dec.status_code, 200)
                self.assertIn('<meta http-equiv="refresh"', r_dec.text)
                self.assertIn(target_redirect, r_dec.text)
                csp = r_dec.headers.get("content-security-policy", "")
                self.assertNotIn("form-action", csp.lower())

                # Unauthenticated HEAD /mcp -> 401 with WWW-Authenticate
                r_head = await client.head(f"{self.facade_base_url}/mcp")
                self.assertEqual(r_head.status_code, 401)
                self.assertIn("www-authenticate", r_head.headers)
                self.assertIn("resource_metadata=", r_head.headers["www-authenticate"])

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e4_upstream_isolation_regression(self) -> None:
        """E4: Direct X-API-Key calls to Mindhub work; direct calls without key get 401; facade never forwards Authorization or client X-API-Key."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Direct X-API-Key call to Mindhub works
                r_direct_ok = await client.get(
                    f"http://127.0.0.1:{self.mindhub_port}/health",
                    headers={"X-API-Key": self.upstream_api_key},
                )
                self.assertEqual(r_direct_ok.status_code, 200)

                # 2. Direct call without key to Mindhub gets 401
                r_direct_no_key = await client.post(
                    f"http://127.0.0.1:{self.mindhub_port}/mcp",
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                self.assertEqual(r_direct_no_key.status_code, 401)

                # 3. Direct call with wrong key to Mindhub gets 401
                r_direct_bad_key = await client.post(
                    f"http://127.0.0.1:{self.mindhub_port}/mcp",
                    headers={"X-API-Key": "wrong-internal-key"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                self.assertEqual(r_direct_bad_key.status_code, 401)

                # 4. Facade call: send client Authorization AND a client-supplied X-API-Key
                tok = f"tok_iso_{secrets.token_hex(16)}"
                self.secrets_to_check.add(tok)
                self.store.create_token(
                    token=tok,
                    kind="access",
                    client_id="iso_client",
                    scope="mindhub:read",
                    resource=self.config.resource,
                    family_id="fam_iso",
                    ttl_seconds=3600,
                )
                client_evil_key = f"evil_key_{secrets.token_hex(8)}"
                self.secrets_to_check.add(client_evil_key)

                rec_count_before = len(self.recording_wrapper.recorded_requests)
                r_proxy = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "X-API-Key": client_evil_key,
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "iso-test", "version": "1.0"},
                        },
                    },
                )
                self.assertEqual(r_proxy.status_code, 200)

                rec_count_after = len(self.recording_wrapper.recorded_requests)
                self.assertGreater(rec_count_after, rec_count_before)

                latest_rec = self.recording_wrapper.recorded_requests[-1]
                rec_headers = latest_rec["headers"]

                # Facade must have injected the internal configured API key
                self.assertEqual(rec_headers.get("x-api-key"), self.upstream_api_key)
                # Facade must NOT forward the client's Authorization header
                self.assertNotIn("authorization", rec_headers)
                # Facade must NOT forward the client's supplied X-API-Key
                self.assertNotIn(client_evil_key, str(rec_headers))

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e5_concurrency(self) -> None:
        """E5: 20 parallel refreshes with same token -> 1x 200, family revoked; 20 parallel code exchanges -> 1x 200."""
        async def run():
            async with httpx.AsyncClient(timeout=10.0) as client:
                cid = "conc_client"
                self.store.create_client(cid, "Concurrent Test Client", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code", "refresh_token"])

                # Part A: 20 parallel refresh requests
                fam_id = "fam_conc_ref"
                ref_tok = f"ref_conc_{secrets.token_hex(16)}"
                self.secrets_to_check.add(ref_tok)
                self.store.create_token(
                    token=ref_tok,
                    kind="refresh",
                    client_id=cid,
                    scope="mindhub:read",
                    resource=self.config.resource,
                    family_id=fam_id,
                    ttl_seconds=3600,
                )

                refresh_tasks = [
                    client.post(
                        f"{self.facade_base_url}/token",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data={
                            "grant_type": "refresh_token",
                            "refresh_token": ref_tok,
                            "client_id": cid,
                        },
                    )
                    for _ in range(20)
                ]
                ref_results = await asyncio.gather(*refresh_tasks)
                ok_refs = [r for r in ref_results if r.status_code == 200]
                fail_refs = [r for r in ref_results if r.status_code == 400]

                self.assertEqual(len(ok_refs), 1, f"Expected exactly 1 refresh 200, got {len(ok_refs)}")
                self.assertEqual(len(fail_refs), 19, f"Expected 19 refresh 400s, got {len(fail_refs)}")

                # Family is revoked afterwards: calling again with newly issued refresh token fails
                new_ref = ok_refs[0].json()["refresh_token"]
                self.secrets_to_check.add(new_ref)
                new_acc = ok_refs[0].json().get("access_token")
                if new_acc:
                    self.secrets_to_check.add(new_acc)

                r_after = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": new_ref,
                        "client_id": cid,
                    },
                )
                self.assertEqual(r_after.status_code, 400)
                self.assertEqual(r_after.json().get("error"), "invalid_grant")

                # Part B: 20 parallel code exchanges
                verifier = secrets.token_urlsafe(48)
                self.secrets_to_check.add(verifier)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
                code = f"code_conc_{secrets.token_hex(16)}"
                self.secrets_to_check.add(code)
                fam_code = "fam_conc_code"
                self.store.create_auth_code(
                    code=code,
                    client_id=cid,
                    redirect_uri="https://claude.ai/api/mcp/auth_callback",
                    code_challenge=challenge,
                    scope="mindhub:read",
                    resource=self.config.resource,
                    family_id=fam_code,
                    ttl_seconds=300,
                )

                code_tasks = [
                    client.post(
                        f"{self.facade_base_url}/token",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data={
                            "grant_type": "authorization_code",
                            "code": code,
                            "client_id": cid,
                            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                            "code_verifier": verifier,
                        },
                    )
                    for _ in range(20)
                ]
                code_results = await asyncio.gather(*code_tasks)
                ok_codes = [r for r in code_results if r.status_code == 200]
                fail_codes = [r for r in code_results if r.status_code == 400]

                self.assertEqual(len(ok_codes), 1, f"Expected exactly 1 code 200, got {len(ok_codes)}")
                self.assertEqual(len(fail_codes), 19, f"Expected 19 code 400s, got {len(fail_codes)}")

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e6_event_loop_non_blocking(self) -> None:
        """E6: While an SSE (GET /mcp) stream is open through facade, GET /health and POST /token respond in < 1s."""
        async def run():
            self.store.create_client("sse_client", "SSE Client", ["https://claude.ai/api/mcp/auth_callback"], ["authorization_code", "refresh_token"])
            tok = f"tok_sse_{secrets.token_hex(16)}"
            self.secrets_to_check.add(tok)
            self.store.create_token(
                token=tok,
                kind="access",
                client_id="sse_client",
                scope="mindhub:read",
                resource=self.config.resource,
                family_id="fam_sse",
                ttl_seconds=3600,
            )

            async with httpx.AsyncClient(timeout=10.0) as client:
                # Initialize to obtain session id
                r_init = await client.post(
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "sse-test", "version": "1.0"},
                        },
                    },
                )
                self.assertEqual(r_init.status_code, 200)
                sess_id = r_init.headers.get("mcp-session-id")
                self.assertIsNotNone(sess_id)

                # Open real Mindhub SSE stream via facade GET /mcp
                async with client.stream(
                    "GET",
                    f"{self.facade_base_url}/mcp",
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Mcp-Session-Id": sess_id,
                        "Accept": "text/event-stream",
                    },
                ) as sse_stream:
                    self.assertEqual(sse_stream.status_code, 200)
                    self.assertIn("text/event-stream", sse_stream.headers.get("content-type", ""))

                    # While the SSE stream is open, measure latency of GET /health
                    t0_health = time.perf_counter()
                    r_health = await client.get(f"{self.facade_base_url}/health")
                    dt_health = time.perf_counter() - t0_health
                    self.assertEqual(r_health.status_code, 200)
                    self.assertLess(dt_health, 1.0, f"GET /health took {dt_health:.4f}s (>= 1.0s)")

                    # Measure latency of POST /token
                    t0_token = time.perf_counter()
                    r_token = await client.post(
                        f"{self.facade_base_url}/token",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data={"grant_type": "client_credentials", "client_id": "sse_client"},
                    )
                    dt_token = time.perf_counter() - t0_token
                    self.assertEqual(r_token.status_code, 400)  # unsupported grant_type
                    self.assertLess(dt_token, 1.0, f"POST /token took {dt_token:.4f}s (>= 1.0s)")

                    # Print report line
                    print(
                        f"\n[E6 Latency] Open SSE: real Mindhub GET /mcp | "
                        f"GET /health: {dt_health * 1000:.2f}ms | "
                        f"POST /token: {dt_token * 1000:.2f}ms"
                    )

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e7_latency_loopback(self) -> None:
        """E7: /register, /authorize, /token, /.well-known/* each respond in < 1s on loopback."""
        async def run():
            latencies: dict[str, float] = {}
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. PRM
                t0 = time.perf_counter()
                r1 = await client.get(f"{self.facade_base_url}/.well-known/oauth-protected-resource")
                latencies["PRM"] = time.perf_counter() - t0
                self.assertEqual(r1.status_code, 200)

                # 2. AS Metadata
                t0 = time.perf_counter()
                r2 = await client.get(f"{self.facade_base_url}/.well-known/oauth-authorization-server")
                latencies["AS_Metadata"] = time.perf_counter() - t0
                self.assertEqual(r2.status_code, 200)

                # 3. /register
                t0 = time.perf_counter()
                r3 = await client.post(
                    f"{self.facade_base_url}/register",
                    json={
                        "client_name": "Latency Client",
                        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                        "grant_types": ["authorization_code"],
                        "response_types": ["code"],
                    },
                )
                latencies["/register"] = time.perf_counter() - t0
                self.assertEqual(r3.status_code, 201)
                cid = r3.json()["client_id"]

                # 4. GET /authorize
                t0 = time.perf_counter()
                r4 = await client.get(
                    f"{self.facade_base_url}/authorize",
                    params={
                        "client_id": cid,
                        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                        "response_type": "code",
                        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "code_challenge_method": "S256",
                    },
                )
                latencies["GET /authorize"] = time.perf_counter() - t0
                self.assertEqual(r4.status_code, 200)

                # 5. POST /token (error or success path)
                t0 = time.perf_counter()
                r5 = await client.post(
                    f"{self.facade_base_url}/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={"grant_type": "authorization_code", "client_id": cid, "code": "dummy_code"},
                )
                latencies["POST /token"] = time.perf_counter() - t0
                self.assertIn(r5.status_code, (400, 200))

                # Assert each < 1.0s
                for name, dt in latencies.items():
                    self.assertLess(dt, 1.0, f"Endpoint {name} took {dt:.4f}s (>= 1.0s)")

                print(
                    "\n[E7 Latencies] " + " | ".join(f"{k}: {v * 1000:.2f}ms" for k, v in latencies.items())
                )

        asyncio.run(asyncio.wait_for(run(), timeout=20.0))

    def test_e8_secret_hygiene(self) -> None:
        """E8: store.scan_all_text_columns() and captured root logs contain NO plaintext secrets."""
        # Ensure a token exists even if run in isolation
        if len(self.secrets_to_check) <= 2:
            alone_tok = f"tok_alone_{secrets.token_hex(16)}"
            self.store.create_token(
                token=alone_tok,
                kind="access",
                client_id="alone_client",
                scope="mindhub:read",
                resource=self.config.resource,
                family_id="fam_alone",
                ttl_seconds=3600,
            )
            self.secrets_to_check.add(alone_tok)

        self.assertGreater(len(self.secrets_to_check), 0, "Expected non-empty secrets set")

        # 1. Scan SQLite DB columns
        all_db_text = self.store.scan_all_text_columns()
        self.assertGreater(len(all_db_text), 0, "Expected non-empty DB text columns")

        for secret in self.secrets_to_check:
            for text_val in all_db_text:
                self.assertNotIn(
                    secret,
                    text_val,
                    f"Plaintext secret leaked into DB column value: {text_val}",
                )

        # 2. Scan captured logs
        all_logs = self.log_handler.get_all_text()
        for secret in self.secrets_to_check:
            self.assertNotIn(
                secret,
                all_logs,
                f"Plaintext secret leaked into log messages: {secret}",
            )


if __name__ == "__main__":
    unittest.main()
