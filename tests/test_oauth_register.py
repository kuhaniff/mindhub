"""Unit tests for Dynamic Client Registration (POST /register)."""
from __future__ import annotations

import os
import tempfile
import unittest

from starlette.testclient import TestClient

from mindhub_oauth.app import create_app
from mindhub_oauth.config import Config
from mindhub_oauth.store import OAuthStore


def make_test_app(extra_env: dict[str, str] | None = None, store: OAuthStore | None = None) -> tuple[TestClient, OAuthStore]:
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    st = store or OAuthStore(db_path)
    env = {
        "FACADE_PUBLIC_URL": "https://mindhub.example.com",
        "MINDHUB_UPSTREAM_API_KEY": "test-key",
        "FACADE_OWNER_PASSWORD_HASH": "scrypt$32768$8$1$c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=$aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
        "FACADE_DB_PATH": db_path,
    }
    if extra_env:
        env.update(extra_env)
    cfg = Config.from_env(env)
    app = create_app(cfg, store=st)
    client = TestClient(app)
    return client, st


class TestOAuthRegister(unittest.TestCase):
    def test_claude_style_registration(self) -> None:
        client, store = make_test_app()
        payload = {
            "client_name": "Claude Desktop",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        }
        res = client.post("/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertIn("client_id", data)
        self.assertIn("client_id_issued_at", data)
        self.assertEqual(data["client_name"], "Claude Desktop")
        self.assertEqual(data["redirect_uris"], ["https://claude.ai/api/mcp/auth_callback"])
        self.assertEqual(data["response_types"], ["code"])
        self.assertEqual(data["token_endpoint_auth_method"], "none")
        self.assertNotIn("client_secret", data)
        self.assertEqual(res.headers.get("cache-control"), "no-store")

    def test_gemini_style_registration_six_uris(self) -> None:
        client, store = make_test_app()
        gemini_uris = [
            "https://oauth-redirect.googleusercontent.com/r/prod1",
            "https://oauth-redirect.googleusercontent.com/a/prod2",
            "https://oauth-redirect-sandbox.googleusercontent.com/r/sand1",
            "https://oauth-redirect-sandbox.googleusercontent.com/a/sand2",
            "https://oauth-redirect.googleusercontent.com/r/prod3",
            "https://oauth-redirect.googleusercontent.com/a/prod4",
        ]
        payload = {
            "client_name": "Gemini Web App",
            "redirect_uris": gemini_uris,
            "token_endpoint_auth_method": "client_secret_post",
        }
        res = client.post("/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(len(data["redirect_uris"]), 6)
        self.assertEqual(data["token_endpoint_auth_method"], "none")
        self.assertNotIn("client_secret", data)

    def test_gemini_style_disallowed_test_host_rejected(self) -> None:
        client, store = make_test_app()
        payload = {
            "client_name": "Gemini Web App",
            "redirect_uris": [
                "https://oauth-redirect-test.googleusercontent.com/r/test-proj"
            ],
        }
        res = client.post("/register", json=payload)
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertEqual(data["error"], "invalid_redirect_uri")

        # Verify audit log recorded rejection with host only
        events = store.get_audit_events()
        self.assertTrue(
            any(
                e.event == "register_rejected"
                and "oauth-redirect-test.googleusercontent.com" in (e.detail or "")
                for e in events
            )
        )

    def test_token_endpoint_auth_method_validation(self) -> None:
        client, store = make_test_app()
        # client_secret_basic accepted as public client
        res = client.post(
            "/register",
            json={
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["token_endpoint_auth_method"], "none")

        # unknown auth method rejected
        res_bad = client.post(
            "/register",
            json={
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "private_key_jwt",
            },
        )
        self.assertEqual(res_bad.status_code, 400)
        self.assertEqual(res_bad.json()["error"], "invalid_client_metadata")

    def test_more_than_six_uris_rejected(self) -> None:
        client, store = make_test_app()
        uris = [f"https://oauth-redirect.googleusercontent.com/r/proj{i}" for i in range(7)]
        res = client.post("/register", json={"redirect_uris": uris})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_redirect_uri")

    def test_non_allowlisted_redirect_rejected(self) -> None:
        client, store = make_test_app()
        res = client.post(
            "/register",
            json={"redirect_uris": ["https://evil.attacker.com/oauth"]},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_redirect_uri")

    def test_oversize_body_rejected(self) -> None:
        client, store = make_test_app()
        oversize_name = "x" * 9000
        res = client.post(
            "/register",
            json={
                "client_name": oversize_name,
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            },
        )
        self.assertIn(res.status_code, (400, 413))

    def test_max_clients_cap(self) -> None:
        client, store = make_test_app(extra_env={"FACADE_MAX_CLIENTS": "2"})
        # 1st succeeds
        r1 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
        )
        self.assertEqual(r1.status_code, 201)
        # 2nd succeeds
        r2 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.com/api/mcp/auth_callback"]},
        )
        self.assertEqual(r2.status_code, 201)
        # 3rd hits cap
        r3 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
        )
        self.assertEqual(r3.status_code, 429)

    def test_register_bad_content_length_400(self) -> None:
        client, _ = make_test_app()
        # Bad non-integer Content-Length must return 400, never 500
        res = client.post(
            "/register",
            content=b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}',
            headers={"Content-Length": "invalid_number", "Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("error"), "invalid_client_metadata")

    def test_register_media_type_split_application_json(self) -> None:
        client, _ = make_test_app()
        # Proper split on ';' allows parameters like charset=utf-8
        res = client.post(
            "/register",
            content=b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        self.assertEqual(res.status_code, 201)

        # Non application/json returns 400
        res_text = client.post(
            "/register",
            content=b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}',
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(res_text.status_code, 400)

    def test_register_stale_client_purged_frees_slot(self) -> None:
        client, store = make_test_app(extra_env={"FACADE_MAX_CLIENTS": "1"})
        # 1st succeeds
        r1 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
        )
        self.assertEqual(r1.status_code, 201)
        # 2nd hits cap
        r2 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
        )
        self.assertEqual(r2.status_code, 429)

        # Advance clock by 25 hours (client becomes stale: no tokens, no auth codes)
        store._conn.execute("UPDATE clients SET last_used_at = last_used_at - 90000.0")
        store.purge_expired(force=True)

        # Now registering succeeds because stale client was purged and freed slot
        r3 = client.post(
            "/register",
            json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
        )
        self.assertEqual(r3.status_code, 201)
        self.assertIn("client_id", r3.json())

    def test_r4_register_dcr_slot_exhaustion_injected_clock(self) -> None:
        current_time = [100000.0]
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_r4.db")
        store = OAuthStore(db_path, now_fn=lambda: current_time[0])
        client, _ = make_test_app(extra_env={"FACADE_MAX_CLIENTS": "2"}, store=store)

        # 1. Register client 1 (never authorized)
        r1 = client.post("/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
        self.assertEqual(r1.status_code, 201)
        c1_id = r1.json()["client_id"]

        # 2. Register client 2 and grant an authorized token
        r2 = client.post("/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
        self.assertEqual(r2.status_code, 201)
        c2_id = r2.json()["client_id"]
        store.create_token(
            token="tok_auth_c2",
            kind="refresh",
            client_id=c2_id,
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_c2",
            ttl_seconds=2592000,
        )

        # 3. FACADE_MAX_CLIENTS (2) is full -> 429
        r3 = client.post("/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
        self.assertEqual(r3.status_code, 429)

        # 4. Advance clock by 61 minutes (3660s)
        current_time[0] += 3660.0

        # 5. Registration succeeds again!
        r4 = client.post("/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
        self.assertEqual(r4.status_code, 201)

        # 6. Authorized client 2 was NOT purged, never-authorized client 1 was purged
        self.assertIsNone(store.get_client(c1_id))
        self.assertIsNotNone(store.get_client(c2_id))

    def test_r5_register_with_invalid_ports_returns_400_never_500(self) -> None:
        client, store = make_test_app()
        for bad_uri in [
            "https://evil.com:99999/",
            "https://oauth-redirect.googleusercontent.com:abc/r/x",
        ]:
            res = client.post(
                "/register",
                json={"redirect_uris": [bad_uri]},
            )
            self.assertEqual(res.status_code, 400)
            data = res.json()
            self.assertEqual(data.get("error"), "invalid_redirect_uri")

    def test_r6_register_input_typing(self) -> None:
        client, store = make_test_app()
        valid_uris = ["https://claude.ai/api/mcp/auth_callback"]

        # grant_types must be a list of str
        res1 = client.post(
            "/register",
            json={"redirect_uris": valid_uris, "grant_types": [[1]]},
        )
        self.assertEqual(res1.status_code, 400)
        self.assertEqual(res1.json().get("error"), "invalid_client_metadata")

        res2 = client.post(
            "/register",
            json={"redirect_uris": valid_uris, "grant_types": [{"a": 1}]},
        )
        self.assertEqual(res2.status_code, 400)
        self.assertEqual(res2.json().get("error"), "invalid_client_metadata")

        # client_name must be a str if present
        res3 = client.post(
            "/register",
            json={"redirect_uris": valid_uris, "client_name": 123},
        )
        self.assertEqual(res3.status_code, 400)
        self.assertEqual(res3.json().get("error"), "invalid_client_metadata")

        # token_endpoint_auth_method must be a str
        res4 = client.post(
            "/register",
            json={"redirect_uris": valid_uris, "token_endpoint_auth_method": ["x"]},
        )
        self.assertEqual(res4.status_code, 400)
        self.assertEqual(res4.json().get("error"), "invalid_client_metadata")


if __name__ == "__main__":
    unittest.main()
