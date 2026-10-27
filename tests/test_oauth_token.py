"""Unit tests for Token endpoint (POST /token) and Revoke (POST /revoke)."""
from __future__ import annotations

import base64
import os
import tempfile
import unittest
import urllib.parse

from starlette.testclient import TestClient

from mindhub_oauth.app import create_app
from mindhub_oauth.config import Config
from mindhub_oauth.security import compute_code_challenge, hash_password
from mindhub_oauth.store import OAuthStore


class TestOAuthToken(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_tok.db")
        self.current_time = 1000.0
        self.store = OAuthStore(self.db_path, now_fn=lambda: self.current_time)
        self.owner_password = "correct-horse-battery-staple-long"
        self.owner_hash = hash_password(self.owner_password)
        self.config = Config.from_env(
            {
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": self.owner_hash,
                "FACADE_MAX_SCOPE": "mindhub:read mindhub:write",
                "FACADE_DEFAULT_SCOPE": "mindhub:read",
                "FACADE_DB_PATH": self.db_path,
            }
        )
        self.app = create_app(self.config, store=self.store)
        self.client = TestClient(self.app)

        # Pre-register client
        self.client_id = "test_client_id"
        self.redirect_uri = "https://claude.ai/api/mcp/auth_callback"
        self.store.create_client(
            client_id=self.client_id,
            client_name="Test App",
            redirect_uris=[self.redirect_uri],
            grant_types=["authorization_code", "refresh_token"],
        )

        # RFC 7636 Appendix B test vector
        self.verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.challenge = compute_code_challenge(self.verifier)

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def _create_auth_code(
        self,
        code: str = "valid_code_123",
        ttl: int = 60,
        family_id: str = "fam_1",
        scope: str = "mindhub:read",
    ) -> str:
        self.store.create_auth_code(
            code=code,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_challenge=self.challenge,
            scope=scope,
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=ttl,
        )
        return code

    def test_happy_path_authorization_code_grant(self) -> None:
        code = self._create_auth_code()
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        res = self.client.post("/token", data=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("cache-control"), "no-store")
        self.assertEqual(res.headers.get("pragma"), "no-cache")

        data = res.json()
        self.assertEqual(data["token_type"], "Bearer")
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertEqual(data["expires_in"], 900)
        self.assertEqual(data["scope"], "mindhub:read")

    def test_code_replay_revokes_family(self) -> None:
        code = self._create_auth_code(family_id="fam_replay")
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        # First exchange succeeds
        res1 = self.client.post("/token", data=payload)
        self.assertEqual(res1.status_code, 200)
        tokens1 = res1.json()

        # Replay attempt fails with invalid_grant
        res2 = self.client.post("/token", data=payload)
        self.assertEqual(res2.status_code, 400)
        self.assertEqual(res2.json()["error"], "invalid_grant")

        # Entire family is revoked!
        self.assertIsNone(self.store.get_access_token(tokens1["access_token"]))

    def test_expired_code_returns_invalid_grant_without_revoking_family(self) -> None:
        code = self._create_auth_code(code="code_expired", ttl=1, family_id="fam_exp")
        # Issue an active token in that family
        self.store.create_token(
            token="active_token_in_fam",
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_exp",
            ttl_seconds=900,
        )

        # Advance store clock past code TTL
        self.current_time += 100.0

        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        res = self.client.post("/token", data=payload)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_grant")

        # Active token must NOT be revoked!
        self.assertIsNotNone(self.store.get_access_token("active_token_in_fam"))

    def test_wrong_verifier_returns_invalid_grant(self) -> None:
        code = self._create_auth_code()
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": "wrong" * 10,
            "redirect_uri": self.redirect_uri,
        }
        res = self.client.post("/token", data=payload)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_grant")

    def test_wrong_redirect_uri_returns_invalid_grant(self) -> None:
        code = self._create_auth_code()
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": "https://claude.com/api/mcp/auth_callback",
        }
        res = self.client.post("/token", data=payload)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_grant")

    def test_basic_auth_header_client_id(self) -> None:
        code = self._create_auth_code()
        auth_header = "Basic " + base64.b64encode(f"{self.client_id}:ignored_secret".encode()).decode()
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        res = self.client.post("/token", data=payload, headers={"Authorization": auth_header})
        self.assertEqual(res.status_code, 200)

    def test_json_body_rejected_properly(self) -> None:
        res = self.client.post(
            "/token",
            json={"grant_type": "authorization_code"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_request")

    def test_unknown_client_returns_401_invalid_client(self) -> None:
        payload = {
            "grant_type": "authorization_code",
            "client_id": "unknown_client_xyz",
            "code": "any_code",
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        res = self.client.post("/token", data=payload)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["error"], "invalid_client")

    def test_refresh_token_rotation(self) -> None:
        # First get tokens
        code = self._create_auth_code(family_id="fam_rot")
        res1 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        tokens1 = res1.json()
        rt1 = tokens1["refresh_token"]

        # Use refresh token to get new tokens
        res2 = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt1,
            },
        )
        self.assertEqual(res2.status_code, 200)
        tokens2 = res2.json()
        self.assertNotEqual(tokens2["access_token"], tokens1["access_token"])
        self.assertNotEqual(tokens2["refresh_token"], rt1)

        # Replaying the OLD refresh token rt1 must fail and revoke whole family!
        res3 = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt1,
            },
        )
        self.assertEqual(res3.status_code, 400)
        self.assertEqual(res3.json()["error"], "invalid_grant")

        # Now tokens2 access token is also revoked!
        self.assertIsNone(self.store.get_access_token(tokens2["access_token"]))

    def test_replaying_used_code_with_malformed_verifier_revokes_family_and_audits(self) -> None:
        code = self._create_auth_code(family_id="fam_malformed_replay")
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }
        # First exchange succeeds
        res1 = self.client.post("/token", data=payload)
        self.assertEqual(res1.status_code, 200)
        tokens = res1.json()
        acc = tokens["access_token"]
        self.assertIsNotNone(self.store.get_access_token(acc))

        # Replay with malformed verifier (short length, invalid chars)
        replay_payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": "short@invalid",
            "redirect_uri": self.redirect_uri,
        }
        res2 = self.client.post("/token", data=replay_payload)
        self.assertEqual(res2.status_code, 400)
        self.assertEqual(res2.json()["error"], "invalid_grant")

        # Family is revoked!
        self.assertIsNone(self.store.get_access_token(acc))

        # Audit event recorded
        events = self.store.get_audit_events()
        self.assertTrue(any(e.event == "auth_code_reuse" and e.client_id == self.client_id for e in events))

    def test_wrong_verifier_on_unused_code_consumes_code(self) -> None:
        code = self._create_auth_code(code="code_wrong_verifier", family_id="fam_wrong_v")
        # 1st attempt: well-formed (43 chars) but wrong verifier
        wrong_verifier = "a" * 43
        res1 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": wrong_verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        self.assertEqual(res1.status_code, 400)
        self.assertEqual(res1.json()["error"], "invalid_grant")

        # 2nd attempt: with the correct verifier, should fail because code was consumed
        res2 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        self.assertEqual(res2.status_code, 400)
        self.assertEqual(res2.json()["error"], "invalid_grant")

        # Audit event for replay recorded
        events = self.store.get_audit_events()
        self.assertTrue(any(e.event == "auth_code_reuse" for e in events))

    def test_revoke_no_client_id_does_not_revoke(self) -> None:
        code = self._create_auth_code(family_id="fam_rev_no_client")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        acc = res.json()["access_token"]

        # Call /revoke with NO client_id
        rev_res = self.client.post("/revoke", data={"token": acc})
        self.assertEqual(rev_res.status_code, 200)
        self.assertEqual(rev_res.headers.get("cache-control"), "no-store")

        # Token is still valid!
        self.assertIsNotNone(self.store.get_access_token(acc))

    def test_revoke_wrong_client_id_does_not_revoke(self) -> None:
        code = self._create_auth_code(family_id="fam_rev_wrong_client")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        acc = res.json()["access_token"]

        # Call /revoke with wrong client_id
        rev_res = self.client.post("/revoke", data={"token": acc, "client_id": "other_client"})
        self.assertEqual(rev_res.status_code, 200)

        # Token is still valid!
        self.assertIsNotNone(self.store.get_access_token(acc))

    def test_revoke_correct_client_id_access_token(self) -> None:
        code = self._create_auth_code(family_id="fam_rev_acc")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        tokens = res.json()
        acc = tokens["access_token"]

        rev_res = self.client.post("/revoke", data={"token": acc, "client_id": self.client_id})
        self.assertEqual(rev_res.status_code, 200)

        # Access token is revoked
        self.assertIsNone(self.store.get_access_token(acc))

    def test_revoke_correct_client_id_refresh_token_revokes_family(self) -> None:
        code = self._create_auth_code(family_id="fam_rev_refresh")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        tokens = res.json()
        acc = tokens["access_token"]
        rt = tokens["refresh_token"]

        # Revoking refresh token revokes whole family
        rev_res = self.client.post("/revoke", data={"token": rt, "client_id": self.client_id})
        self.assertEqual(rev_res.status_code, 200)

        # Access token in that family is now dead
        self.assertIsNone(self.store.get_access_token(acc))

    def test_revoke_basic_auth_client_id(self) -> None:
        code = self._create_auth_code(family_id="fam_rev_basic")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        acc = res.json()["access_token"]

        auth_header = "Basic " + base64.b64encode(f"{self.client_id}:ignored".encode()).decode()
        rev_res = self.client.post(
            "/revoke",
            data={"token": acc},
            headers={"Authorization": auth_header},
        )
        self.assertEqual(rev_res.status_code, 200)
        self.assertIsNone(self.store.get_access_token(acc))

    def test_refresh_wrong_client_does_not_burn_token(self) -> None:
        # Create second client
        self.store.create_client(
            client_id="client_2",
            client_name="Client 2",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code", "refresh_token"],
        )
        code = self._create_auth_code(family_id="fam_wrong_client_refresh")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        rt = res.json()["refresh_token"]

        # Attempt refresh with client_2 (mismatch)
        r_fail = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "client_2",
                "refresh_token": rt,
            },
        )
        self.assertEqual(r_fail.status_code, 400)
        self.assertEqual(r_fail.json()["error"], "invalid_grant")

        # Verify token was NOT burned: refresh with legitimate client_id succeeds!
        r_ok = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
            },
        )
        self.assertEqual(r_ok.status_code, 200)
        self.assertIn("access_token", r_ok.json())

    def test_refresh_invalid_scope_broadening_does_not_burn_token(self) -> None:
        code = self._create_auth_code(scope="mindhub:read", family_id="fam_scope_refresh")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        rt = res.json()["refresh_token"]

        # Attempt to broaden scope to include mindhub:write
        r_fail = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
                "scope": "mindhub:read mindhub:write",
            },
        )
        self.assertEqual(r_fail.status_code, 400)
        self.assertEqual(r_fail.json()["error"], "invalid_scope")

        # Token was NOT burned: refreshing without broadening succeeds!
        r_ok = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
                "scope": "mindhub:read",
            },
        )
        self.assertEqual(r_ok.status_code, 200)

    def test_refresh_scope_narrowing_works(self) -> None:
        code = self._create_auth_code(scope="mindhub:read mindhub:write", family_id="fam_narrow_refresh")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        rt = res.json()["refresh_token"]

        # Narrow scope to mindhub:read only
        r_narrow = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
                "scope": "mindhub:read",
            },
        )
        self.assertEqual(r_narrow.status_code, 200)
        self.assertEqual(r_narrow.json()["scope"], "mindhub:read")

    def test_refresh_replay_of_used_token_revokes_family(self) -> None:
        code = self._create_auth_code(family_id="fam_rt_replay")
        res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        rt = res.json()["refresh_token"]

        # 1st rotation: succeeds
        r1 = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
            },
        )
        self.assertEqual(r1.status_code, 200)
        new_acc = r1.json()["access_token"]
        self.assertIsNotNone(self.store.get_access_token(new_acc))

        # Replay old rt: fails and revokes whole family!
        r_replay = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt,
            },
        )
        self.assertEqual(r_replay.status_code, 400)
        self.assertEqual(r_replay.json()["error"], "invalid_grant")
        # Newly issued access token is now revoked
        self.assertIsNone(self.store.get_access_token(new_acc))

    def test_token_and_revoke_content_type_parsing_and_multipart_boundary_400(self) -> None:
        # Proper split on ';' allows charset parameter
        code = self._create_auth_code(family_id="fam_ct_test")
        body = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": self.verifier,
            "redirect_uri": self.redirect_uri,
        }).encode()

        res_ok = self.client.post(
            "/token",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        )
        self.assertEqual(res_ok.status_code, 200)

        # Multipart with boundary substringing application/x-www-form-urlencoded => 400
        res_bad = self.client.post(
            "/token",
            content=b"dummy",
            headers={"Content-Type": "multipart/form-data; boundary=application/x-www-form-urlencoded"},
        )
        self.assertEqual(res_bad.status_code, 400)
        self.assertEqual(res_bad.json()["error"], "invalid_request")

        # Same for /revoke
        res_rev_bad = self.client.post(
            "/revoke",
            content=b"token=abc",
            headers={"Content-Type": "multipart/form-data; boundary=application/x-www-form-urlencoded"},
        )
        self.assertEqual(res_rev_bad.status_code, 400)
        self.assertEqual(res_rev_bad.json()["error"], "invalid_request")

    def test_audit_events_and_no_secrets_leaked(self) -> None:
        # 1. Register
        reg_res = self.client.post(
            "/register",
            json={"client_name": "Audit Client", "redirect_uris": [self.redirect_uri]},
        )
        self.assertEqual(reg_res.status_code, 201)
        cid = reg_res.json()["client_id"]

        # 2. Authorize reject
        self.client.get("/authorize?client_id=nonexistent_for_audit")

        # 3. Decision wrong password -> login_failed
        auth_res = self.client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "code_challenge": self.challenge,
                "code_challenge_method": "S256",
            },
        )
        cookie_header = auth_res.headers.get("set-cookie", "")
        csrf_val = cookie_header.split("mh_csrf=")[1].split(";")[0]
        import re
        req_id = re.search(r'name="request_id"\s+value="([^"]+)"', auth_res.text).group(1)

        self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf_val,
                "password": "wrong-secret-password-attempt",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={csrf_val}"},
        )

        # 4. Decision deny -> authorization_denied
        self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf_val,
                "action": "deny",
            },
            headers={"Cookie": f"mh_csrf={csrf_val}"},
        )

        # 5. Decision allow -> authorization_granted
        auth_res2 = self.client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "code_challenge": self.challenge,
                "code_challenge_method": "S256",
            },
        )
        csrf_val2 = auth_res2.headers.get("set-cookie", "").split("mh_csrf=")[1].split(";")[0]
        req_id2 = re.search(r'name="request_id"\s+value="([^"]+)"', auth_res2.text).group(1)
        allow_res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id2,
                "csrf": csrf_val2,
                "password": "correct-horse-battery-staple-long",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={csrf_val2}"},
            follow_redirects=False,
        )
        loc = allow_res.headers.get("location", "")
        code_issued = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["code"][0]

        # 6. Token issued -> token_issued
        tok_res = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": cid,
                "code": code_issued,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            },
        )
        self.assertEqual(tok_res.status_code, 200)
        tokens = tok_res.json()
        acc = tokens["access_token"]
        rt = tokens["refresh_token"]

        # 7. Token refreshed -> token_refreshed
        ref_res = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": cid,
                "refresh_token": rt,
            },
        )
        self.assertEqual(ref_res.status_code, 200)
        new_acc = ref_res.json()["access_token"]

        # 8. Token revoked -> token_revoked
        self.client.post("/revoke", data={"token": new_acc, "client_id": cid})

        # Verify all expected event types exist in audit log
        events = self.store.get_audit_events()
        event_names = {e.event for e in events}
        self.assertIn("register_ok", event_names)
        self.assertIn("authorize_rejected", event_names)
        self.assertIn("login_failed", event_names)
        self.assertIn("authorization_denied", event_names)
        self.assertIn("authorization_granted", event_names)
        self.assertIn("token_issued", event_names)
        self.assertIn("token_refreshed", event_names)
        self.assertIn("token_revoked", event_names)

        # Check for any secret leak in audit table (tokens, verifiers, passwords)
        with self.store.connection() as conn:
            rows = conn.execute("SELECT event, detail FROM audit").fetchall()
            for row in rows:
                detail = row["detail"] or ""
                self.assertNotIn("correct-horse", detail)
                self.assertNotIn("wrong-secret", detail)
                self.assertNotIn(self.verifier, detail)
                self.assertNotIn(acc, detail)
                self.assertNotIn(rt, detail)
                self.assertNotIn(new_acc, detail)

    def test_r9_refresh_scope_rules(self) -> None:
        # Create a refresh token with scope "mindhub:read"
        rt_read_only = "rt_scope_read_only"
        self.store.create_token(
            token=rt_read_only,
            kind="refresh",
            client_id=self.client_id,
            scope="mindhub:read",
            resource=self.config.resource,
            family_id="fam_scope_ro",
            ttl_seconds=3600,
        )

        # 1. Scope is whitespace only " " -> treated as not supplied, succeeds with original scope
        res_ws = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt_read_only,
                "scope": "   ",
            },
        )
        self.assertEqual(res_ws.status_code, 200)
        self.assertEqual(res_ws.json()["scope"], "mindhub:read")
        new_rt = res_ws.json()["refresh_token"]

        # 2. Scope "offline_access" only (missing mindhub:read) -> 400 invalid_scope, token NOT burned
        res_off = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": new_rt,
                "scope": "offline_access",
            },
        )
        self.assertEqual(res_off.status_code, 400)
        self.assertEqual(res_off.json()["error"], "invalid_scope")

        # Verify token NOT burned by calling again with valid scope
        res_retry = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": new_rt,
            },
        )
        self.assertEqual(res_retry.status_code, 200)
        new_rt2 = res_retry.json()["refresh_token"]

        # 3. Scope "mindhub:write" when original was read-only -> 400 invalid_scope, token NOT burned
        res_broaden = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": new_rt2,
                "scope": "mindhub:write",
            },
        )
        self.assertEqual(res_broaden.status_code, 400)
        self.assertEqual(res_broaden.json()["error"], "invalid_scope")

        # 4. Valid narrowing: create token with "mindhub:read mindhub:write offline_access" and request "mindhub:read"
        rt_multi = "rt_scope_multi"
        self.store.create_token(
            token=rt_multi,
            kind="refresh",
            client_id=self.client_id,
            scope="mindhub:read mindhub:write offline_access",
            resource=self.config.resource,
            family_id="fam_scope_multi",
            ttl_seconds=3600,
        )
        res_narrow = self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": rt_multi,
                "scope": "mindhub:read",
            },
        )
        self.assertEqual(res_narrow.status_code, 200)
        self.assertEqual(res_narrow.json()["scope"], "mindhub:read")

    def test_r10_revoke_audit_and_unsupported_grant_type_echo(self) -> None:
        # 1. Revoking unknown token returns 200 but audits nothing
        audit_count_before = len(self.store.get_audit_events())
        res_unknown = self.client.post(
            "/revoke",
            data={"token": "completely_unknown_token", "client_id": self.client_id},
        )
        self.assertEqual(res_unknown.status_code, 200)
        events_after = self.store.get_audit_events()
        self.assertEqual(len(events_after), audit_count_before)

        # 2. Revoking valid token returns 200 and audits token_revoked
        tok = "tok_to_revoke_r10"
        self.store.create_token(
            token=tok,
            kind="access",
            client_id=self.client_id,
            scope="mindhub:read",
            resource=self.config.resource,
            family_id="fam_r10",
            ttl_seconds=3600,
        )
        res_valid = self.client.post(
            "/revoke",
            data={"token": tok, "client_id": self.client_id},
        )
        self.assertEqual(res_valid.status_code, 200)
        events_valid = self.store.get_audit_events()
        self.assertEqual(len(events_valid), audit_count_before + 1)
        self.assertEqual(events_valid[-1].event, "token_revoked")

        # 3. Echoed grant_type in /token error truncated and sanitized to 64 ASCII chars
        long_bad_grant = "malicious\x00\x1f\x7f\U0001f600" + ("z" * 200)
        res_bad_gt = self.client.post(
            "/token",
            data={"grant_type": long_bad_grant, "client_id": self.client_id},
        )
        self.assertEqual(res_bad_gt.status_code, 400)
        err_desc = res_bad_gt.json().get("error_description", "")
        # Should not leak control/non-ASCII characters
        self.assertNotIn("\x00", err_desc)
        self.assertNotIn("\x1f", err_desc)
        self.assertNotIn("\x7f", err_desc)
        self.assertNotIn("\U0001f600", err_desc)
        # Prefix "Unsupported grant_type: " is 24 chars, echoed part <= 64 chars
        echoed_part = err_desc.replace("Unsupported grant_type: ", "")
        self.assertLessEqual(len(echoed_part), 64)
        self.assertTrue(echoed_part.isascii())


if __name__ == "__main__":
    unittest.main()
