"""Unit tests for Authorize endpoint (GET /authorize)."""
from __future__ import annotations

import html
import os
import re
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

from starlette.testclient import TestClient

from mindhub_oauth.app import create_app
from mindhub_oauth.config import Config
from mindhub_oauth.security import hash_password
from mindhub_oauth.store import OAuthStore


class TestOAuthAuthorize(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_auth.db")
        self.store = OAuthStore(self.db_path)
        self.config = Config.from_env(
            {
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": "scrypt$32768$8$1$c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=$aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
                "FACADE_MAX_SCOPE": "mindhub:read mindhub:write",
                "FACADE_DEFAULT_SCOPE": "mindhub:read",
                "FACADE_DB_PATH": self.db_path,
            }
        )
        self.app = create_app(self.config, store=self.store)
        self.client = TestClient(self.app)

        # Pre-register a client
        self.client_rec = self.store.create_client(
            client_id="registered_client",
            client_name="Test Application <script>alert('xss')</script>",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code", "refresh_token"],
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def test_unknown_client_renders_html_error_no_redirect(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": "unknown_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "code",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertNotIn("location", res.headers)
        self.assertIn("Invalid client", res.text)

    def test_unregistered_redirect_uri_renders_html_error_no_redirect(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://evil.com/callback",
                "response_type": "code",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertNotIn("location", res.headers)
        self.assertIn("Invalid redirect URI", res.text)

    def test_missing_or_plain_pkce_redirects_with_error(self) -> None:
        # Missing PKCE
        res1 = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "code",
                "state": "state1",
            },
            follow_redirects=False,
        )
        self.assertEqual(res1.status_code, 302)
        loc1 = res1.headers["location"]
        self.assertIn("error=invalid_request", loc1)
        self.assertIn("state=state1", loc1)
        self.assertIn("iss=https%3A%2F%2Fmindhub.example.com", loc1)

        # Plain PKCE
        res2 = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "code",
                "code_challenge": "plain_challenge",
                "code_challenge_method": "plain",
                "state": "state2",
            },
            follow_redirects=False,
        )
        self.assertEqual(res2.status_code, 302)
        loc2 = res2.headers["location"]
        self.assertIn("error=invalid_request", loc2)
        self.assertIn("state=state2", loc2)

    def test_invalid_code_challenge_charset_redirects(self) -> None:
        # 43 chars with invalid base64url characters (+, /, =)
        invalid_challenges = [
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c+",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c/",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c@",
        ]
        for ch in invalid_challenges:
            with self.subTest(challenge=ch):
                res = self.client.get(
                    "/authorize",
                    params={
                        "client_id": "registered_client",
                        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                        "response_type": "code",
                        "code_challenge": ch,
                        "code_challenge_method": "S256",
                        "state": "state_charset",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(res.status_code, 302)
                loc = res.headers["location"]
                self.assertIn("error=invalid_request", loc)
                self.assertIn("state=state_charset", loc)
                self.assertIn("iss=https%3A%2F%2Fmindhub.example.com", loc)

    def test_unsupported_response_type_redirects(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "token",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "state": "state3",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertIn("error=unsupported_response_type", res.headers["location"])

    def test_invalid_target_resource_redirects(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "resource": "https://wrong.resource.com/mcp",
                "state": "state4",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertIn("error=invalid_target", res.headers["location"])

    def test_valid_authorize_creates_pending_auth(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": "registered_client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "scope": "mindhub:read mindhub:write",
                "state": "valid_state_123",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        # Verify CSRF cookie set
        self.assertIn("mh_csrf", res.cookies)
        # Verify security headers
        self.assertEqual(res.headers.get("x-frame-options"), "DENY")
        self.assertEqual(res.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(res.headers.get("referrer-policy"), "no-referrer")
        csp = res.headers.get("content-security-policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("form-action", csp)
        # Verify XSS payload was escaped
        self.assertNotIn("<script>", res.text)
        self.assertIn("&lt;script&gt;", res.text)


class TestOAuthAuthorizeDecision(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_decision.db")
        self.current_time = 1000.0
        self.store = OAuthStore(self.db_path, now_fn=lambda: self.current_time)
        self.owner_password = "owner-valid-password-12345"
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
        self.client = TestClient(self.app, client=("127.0.0.1", 50000))

        # Pre-register a client with Claude and Google redirect URIs
        self.client_id = "test_client_decision"
        self.claude_redirect = "https://claude.ai/api/mcp/auth_callback"
        self.google_redirect = "https://oauth-redirect.googleusercontent.com/r/myproj"
        self.store.create_client(
            client_id=self.client_id,
            client_name="Test Decision App",
            redirect_uris=[self.claude_redirect, self.google_redirect],
            grant_types=["authorization_code", "refresh_token"],
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def _get_pending_auth(
        self,
        scope: str = "mindhub:read mindhub:write",
        redirect_uri: str | None = None,
        state: str = "test_state_123",
    ) -> tuple[str, str, str]:
        """Call GET /authorize to obtain a valid (request_id, csrf, cookie)."""
        redirect = redirect_uri or self.claude_redirect
        res = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "scope": scope,
                "state": state,
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 200)
        cookie = res.cookies.get("mh_csrf", "")

        # Extract hidden input fields request_id and csrf
        req_match = re.search(r'name="request_id"\s+value="([^"]+)"', res.text)
        csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', res.text)
        self.assertIsNotNone(req_match)
        self.assertIsNotNone(csrf_match)
        return req_match.group(1), csrf_match.group(1), cookie

    def test_decision_csrf_missing_or_mismatch(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth()

        # 1. Missing cookie
        res1 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
        )
        self.assertEqual(res1.status_code, 400)
        self.assertIn("CSRF", res1.text)

        # 2. Missing form field
        res2 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
        )
        self.assertEqual(res2.status_code, 400)

        # 3. Mismatched cookie vs form
        res3 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": "mh_csrf=wrong_cookie_value"},
        )
        self.assertEqual(res3.status_code, 400)

        # 4. Form field matches cookie, but not the stored hash
        fake_csrf = "fake_csrf_value_matching_cookie_123"
        res4 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": fake_csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={fake_csrf}"},
        )
        self.assertEqual(res4.status_code, 400)

    def test_decision_wrong_password(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth()
        res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": "incorrect_password",
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("password", res.text.lower())

    def test_decision_lockout_after_5_and_no_password_check_while_locked(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth()

        # 5 wrong attempts from the same IP
        for _ in range(5):
            res = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id,
                    "csrf": csrf,
                    "password": "wrong_password",
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie}", "CF-Connecting-IP": "198.51.100.55"},
            )
            self.assertEqual(res.status_code, 401)

        # 6th attempt: should be locked out (429) WITHOUT running verify_password
        with patch("mindhub_oauth.routes.verify_password") as mock_verify:
            res6 = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id,
                    "csrf": csrf,
                    "password": self.owner_password,
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie}", "CF-Connecting-IP": "198.51.100.55"},
            )
            self.assertEqual(res6.status_code, 429)
            self.assertIn("Too many", res6.text)
            mock_verify.assert_not_called()

    def test_decision_global_lockout(self) -> None:
        # 20 failures across 20 distinct IPs
        for i in range(20):
            req_id, csrf, cookie = self._get_pending_auth()
            ip = f"198.51.100.{i + 1}"
            res = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id,
                    "csrf": csrf,
                    "password": "wrong_password",
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie}", "CF-Connecting-IP": ip},
            )
            self.assertEqual(res.status_code, 401)

        # 21st attempt from a brand-new IP (198.51.100.99) hits global lockout
        req_id, csrf, cookie = self._get_pending_auth()
        with patch("mindhub_oauth.routes.verify_password") as mock_verify:
            res21 = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id,
                    "csrf": csrf,
                    "password": self.owner_password,
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie}", "CF-Connecting-IP": "198.51.100.99"},
            )
            self.assertEqual(res21.status_code, 429)
            mock_verify.assert_not_called()

    def test_decision_expired_or_used_request_id(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth()

        # Successfully authorize first
        res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)

        # Attempt to reuse the consumed request_id
        res_reused = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
        )
        self.assertEqual(res_reused.status_code, 400)

        # Expired request_id test
        req_id2, csrf2, cookie2 = self._get_pending_auth()
        self.current_time += 700.0  # past 600s TTL
        res_exp = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id2,
                "csrf": csrf2,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie2}"},
        )
        self.assertEqual(res_exp.status_code, 400)

    def test_decision_deny(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth(state="my_deny_state")
        res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "action": "deny",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        loc = res.headers["location"]
        self.assertIn("error=access_denied", loc)
        self.assertIn("state=my_deny_state", loc)
        self.assertIn("iss=https%3A%2F%2Fmindhub.example.com", loc)

        # Re-submitting denied request_id fails because it was consumed
        res2 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "action": "deny",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
        )
        self.assertEqual(res2.status_code, 400)

    def test_decision_scope_intersection_never_broadens(self) -> None:
        # Case A: Request both scopes, user chooses read-only
        req_id1, csrf1, c1 = self._get_pending_auth(scope="mindhub:read mindhub:write")
        res1 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id1,
                "csrf": csrf1,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={c1}"},
            follow_redirects=False,
        )
        self.assertEqual(res1.status_code, 302)
        code1 = urllib.parse.parse_qs(urllib.parse.urlsplit(res1.headers["location"]).query)["code"][0]
        # Exchange code and check granted scope
        tok_res1 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code1,
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "redirect_uri": self.claude_redirect,
            },
        )
        self.assertEqual(tok_res1.json()["scope"], "mindhub:read")

        # Case B: Request both scopes, user chooses readwrite
        req_id2, csrf2, c2 = self._get_pending_auth(scope="mindhub:read mindhub:write")
        res2 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id2,
                "csrf": csrf2,
                "password": self.owner_password,
                "scope_choice": "readwrite",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={c2}"},
            follow_redirects=False,
        )
        self.assertEqual(res2.status_code, 302)
        code2 = urllib.parse.parse_qs(urllib.parse.urlsplit(res2.headers["location"]).query)["code"][0]
        tok_res2 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code2,
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "redirect_uri": self.claude_redirect,
            },
        )
        self.assertIn("mindhub:read", tok_res2.json()["scope"])
        self.assertIn("mindhub:write", tok_res2.json()["scope"])

        # Case C: Request read-only, but form tampers scope_choice to "readwrite"
        req_id3, csrf3, c3 = self._get_pending_auth(scope="mindhub:read")
        res3 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id3,
                "csrf": csrf3,
                "password": self.owner_password,
                "scope_choice": "readwrite",  # tampering attempt
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={c3}"},
            follow_redirects=False,
        )
        self.assertEqual(res3.status_code, 302)
        code3 = urllib.parse.parse_qs(urllib.parse.urlsplit(res3.headers["location"]).query)["code"][0]
        tok_res3 = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code3,
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "redirect_uri": self.claude_redirect,
            },
        )
        # MUST remain mindhub:read only!
        self.assertEqual(tok_res3.json()["scope"], "mindhub:read")

    def test_decision_claude_host_returns_302(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth(redirect_uri=self.claude_redirect, state="claude_state")
        res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers.get("cache-control"), "no-store")
        loc = res.headers["location"]
        self.assertTrue(loc.startswith(self.claude_redirect))
        self.assertIn("code=", loc)
        self.assertIn("state=claude_state", loc)
        self.assertIn("iss=https%3A%2F%2Fmindhub.example.com", loc)

    def test_decision_google_host_returns_200_meta_refresh_with_escaped_url(self) -> None:
        req_id, csrf, cookie = self._get_pending_auth(redirect_uri=self.google_redirect, state="google_state_123")
        res = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertEqual(res.headers.get("cache-control"), "no-store")
        self.assertIn("<meta http-equiv=\"refresh\"", res.text)
        self.assertIn("google_state_123", res.text)
        self.assertIn("<a href=", res.text)

        # Flag off returns 302
        env_no_meta = dict(os.environ)
        env_no_meta.update(
            {
                "FACADE_PUBLIC_URL": "https://mindhub.example.com",
                "MINDHUB_UPSTREAM_API_KEY": "test-key",
                "FACADE_OWNER_PASSWORD_HASH": self.owner_hash,
                "FACADE_GOOGLE_META_REFRESH": "0",
                "FACADE_DB_PATH": self.db_path,
            }
        )
        app_no_meta = create_app(Config.from_env(env_no_meta), store=self.store)
        client_no_meta = TestClient(app_no_meta, client=("127.0.0.1", 50000))

        res_auth = client_no_meta.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.google_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
        )
        c_val = res_auth.cookies.get("mh_csrf", "")
        r_id = re.search(r'name="request_id"\s+value="([^"]+)"', res_auth.text).group(1)
        c_id = re.search(r'name="csrf"\s+value="([^"]+)"', res_auth.text).group(1)

        res_302 = client_no_meta.post(
            "/authorize/decision",
            data={
                "request_id": r_id,
                "csrf": c_id,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={c_val}"},
            follow_redirects=False,
        )
        self.assertEqual(res_302.status_code, 302)

    def test_decision_xss_payloads_in_client_name_state_redirect(self) -> None:
        xss_client_id = "xss_client_id"
        self.store.create_client(
            client_id=xss_client_id,
            client_name="Evil <script>alert('xss_name')</script>",
            redirect_uris=["https://oauth-redirect.googleusercontent.com/r/xss_proj"],
            grant_types=["authorization_code"],
        )
        xss_state = '"><script>alert("xss_state")</script>'
        res = self.client.get(
            "/authorize",
            params={
                "client_id": xss_client_id,
                "redirect_uri": "https://oauth-redirect.googleusercontent.com/r/xss_proj",
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "state": xss_state,
            },
        )
        self.assertEqual(res.status_code, 200)
        # Script tags must be escaped
        self.assertNotIn("<script>alert('xss_name')</script>", res.text)
        self.assertIn("&lt;script&gt;alert(&#x27;xss_name&#x27;)&lt;/script&gt;", res.text)

        r_id = re.search(r'name="request_id"\s+value="([^"]+)"', res.text).group(1)
        c_id = re.search(r'name="csrf"\s+value="([^"]+)"', res.text).group(1)
        c_cookie = res.cookies.get("mh_csrf", "")

        # Allow decision with Google meta-refresh response
        res_dec = self.client.post(
            "/authorize/decision",
            data={
                "request_id": r_id,
                "csrf": c_id,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={c_cookie}"},
        )
        self.assertEqual(res_dec.status_code, 200)
        self.assertNotIn("<script>", res_dec.text)
        self.assertEqual(res_dec.status_code, 200)
        self.assertNotIn("<script>", res_dec.text)

    def test_decision_security_headers_including_no_form_action(self) -> None:
        # Check GET /authorize
        res1 = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
        )
        csp = res1.headers.get("content-security-policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("form-action", csp)
        self.assertEqual(res1.headers.get("x-frame-options"), "DENY")
        self.assertEqual(res1.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(res1.headers.get("referrer-policy"), "no-referrer")
        self.assertEqual(res1.headers.get("cache-control"), "no-store")

        # Check POST /authorize/decision error page
        res2 = self.client.post("/authorize/decision", data={})
        self.assertEqual(res2.headers.get("x-frame-options"), "DENY")
        csp2 = res2.headers.get("content-security-policy", "")
        self.assertNotIn("form-action", csp2)

    def test_decision_cookie_attributes(self) -> None:
        res = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
        )
        set_cookie = res.headers.get("set-cookie", "")
        self.assertIn("mh_csrf=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Path=/authorize", set_cookie)
        self.assertIn("samesite=lax", set_cookie.lower())
        self.assertIn("Max-Age=600", set_cookie)
        self.assertIn("Secure", set_cookie)

    def test_authorize_rate_limiting_429(self) -> None:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.claude_redirect,
            "response_type": "code",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        # First 30 requests within 1 minute succeed
        for _ in range(30):
            res = self.client.get("/authorize", params=params)
            self.assertEqual(res.status_code, 200)

        # 31st request exceeds rate limit -> 429 HTML error
        res_blocked = self.client.get("/authorize", params=params)
        self.assertEqual(res_blocked.status_code, 429)
        self.assertIn("Rate limit exceeded", res_blocked.text)

    def test_authorize_state_length_cap_4096(self) -> None:
        # 1. 4096 chars is accepted
        valid_state_4096 = "s" * 4096
        res_ok = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "state": valid_state_4096,
            },
            follow_redirects=False,
        )
        self.assertEqual(res_ok.status_code, 200)
        self.assertEqual(self.store.count_active_pending_authorizations(), 1)

        # 2. 4097 chars is rejected
        long_state_4097 = "x" * 4097
        res_err = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "state": long_state_4097,
            },
            follow_redirects=False,
        )
        self.assertEqual(res_err.status_code, 302)
        loc = res_err.headers.get("location", "")
        self.assertTrue(loc.startswith(self.claude_redirect))
        parsed = urllib.parse.urlsplit(loc)
        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs.get("error"), ["invalid_request"])
        self.assertEqual(qs.get("iss"), [self.config.issuer])
        self.assertEqual(qs.get("state"), [long_state_4097])
        # Assert no additional DB row was created for the rejected attempt
        self.assertEqual(self.store.count_active_pending_authorizations(), 1)

        # Check audit log: must contain len=4097 and MUST NOT contain the state itself
        audit = self.store.get_audit_events()
        reject_events = [e for e in audit if e.event == "authorize_rejected"]
        self.assertTrue(
            any("reason=state_too_long len=4097" in (e.detail or "") for e in reject_events),
            f"Expected audit with 'reason=state_too_long len=4097' in {reject_events}",
        )
        self.assertFalse(
            any(long_state_4097 in (e.detail or "") for e in reject_events),
            "State value must not appear in audit log",
        )

    def test_e2e_long_state_roundtrip_2048_and_4096_claude_and_google(self) -> None:
        """Verify long states (2048 and 4096 chars) round-trip byte-identically in 302 and 200 meta-refresh."""
        for size in (2048, 4096):
            # Create a structured string of exact length `size`
            raw_state = f"state_prefix_{size}_" + ("x" * (size - len(f"state_prefix_{size}_") - 1)) + "Z"
            self.assertEqual(len(raw_state), size)

            # A. Normal client: 302 redirect
            req_id, csrf, cookie = self._get_pending_auth(redirect_uri=self.claude_redirect, state=raw_state)
            res_302 = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id,
                    "csrf": csrf,
                    "password": self.owner_password,
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie}"},
                follow_redirects=False,
            )
            self.assertEqual(res_302.status_code, 302)
            loc = res_302.headers.get("location", "")
            parsed_302 = urllib.parse.urlsplit(loc)
            qs_302 = urllib.parse.parse_qs(parsed_302.query)
            self.assertEqual(qs_302.get("state"), [raw_state])
            self.assertEqual(len(qs_302["state"][0]), size)

            # B. Google redirect URI: 200 meta-refresh
            req_id_g, csrf_g, cookie_g = self._get_pending_auth(redirect_uri=self.google_redirect, state=raw_state)
            res_200 = self.client.post(
                "/authorize/decision",
                data={
                    "request_id": req_id_g,
                    "csrf": csrf_g,
                    "password": self.owner_password,
                    "scope_choice": "read",
                    "action": "allow",
                },
                headers={"Cookie": f"mh_csrf={cookie_g}"},
                follow_redirects=False,
            )
            self.assertEqual(res_200.status_code, 200)
            self.assertIn("<meta http-equiv=\"refresh\"", res_200.text)
            # Extract target from meta tag
            m_meta = re.search(r'content="0;url=([^"]+)"', res_200.text)
            self.assertIsNotNone(m_meta)
            escaped_meta_url = m_meta.group(1)
            unescaped_meta_url = html.unescape(escaped_meta_url)
            parsed_meta = urllib.parse.urlsplit(unescaped_meta_url)
            qs_meta = urllib.parse.parse_qs(parsed_meta.query)
            self.assertEqual(qs_meta.get("state"), [raw_state])
            self.assertEqual(len(qs_meta["state"][0]), size)

            # Extract target from fallback link
            m_link = re.search(r'<a href="([^"]+)"', res_200.text)
            self.assertIsNotNone(m_link)
            self.assertEqual(m_link.group(1), escaped_meta_url)

    def test_e2e_special_characters_state_roundtrip_and_meta_refresh_escaped(self) -> None:
        """Verify state with quotes, <, >, &, and non-ASCII characters is properly escaped and round-trips."""
        special_state = 'state_test_"quotes"_\'<tag>_&_amp_日本語_€_ñ_123'

        # 1. Normal client (302 Location header)
        req_id, csrf, cookie = self._get_pending_auth(redirect_uri=self.claude_redirect, state=special_state)
        res_302 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie}"},
            follow_redirects=False,
        )
        self.assertEqual(res_302.status_code, 302)
        loc = res_302.headers.get("location", "")
        parsed_302 = urllib.parse.urlsplit(loc)
        qs_302 = urllib.parse.parse_qs(parsed_302.query)
        self.assertEqual(qs_302.get("state"), [special_state])

        # 2. Google redirect URI (200 meta-refresh HTML response)
        req_id_g, csrf_g, cookie_g = self._get_pending_auth(redirect_uri=self.google_redirect, state=special_state)
        res_200 = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id_g,
                "csrf": csrf_g,
                "password": self.owner_password,
                "scope_choice": "read",
                "action": "allow",
            },
            headers={"Cookie": f"mh_csrf={cookie_g}"},
            follow_redirects=False,
        )
        self.assertEqual(res_200.status_code, 200)

        # Confirm dangerous raw HTML characters are escaped in the rendered page
        self.assertNotIn("<tag>", res_200.text)
        self.assertNotIn('"quotes"', res_200.text)

        # Extract target from meta tag
        m_meta = re.search(r'content="0;url=([^"]+)"', res_200.text)
        self.assertIsNotNone(m_meta)
        unescaped_meta_url = html.unescape(m_meta.group(1))
        parsed_meta = urllib.parse.urlsplit(unescaped_meta_url)
        qs_meta = urllib.parse.parse_qs(parsed_meta.query)
        self.assertEqual(qs_meta.get("state"), [special_state])

    def test_authorize_pending_cap_200_html_429(self) -> None:
        # Pre-fill 200 active pending authorizations
        for i in range(200):
            self.store.create_pending_authorization(
                request_id=f"cap_req_{i}",
                client_id=self.client_id,
                redirect_uri=self.claude_redirect,
                state="s",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                scope="mindhub:read",
                resource=self.config.resource,
                csrf=f"csrf_{i}",
                ttl_seconds=600,
            )
        self.assertEqual(self.store.count_active_pending_authorizations(), 200)

        res = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(res.status_code, 429)
        self.assertIn("Too Many Requests", res.text)
        # Cap blocked new row creation: still 200
        self.assertEqual(self.store.count_active_pending_authorizations(), 200)

    def test_authorize_decision_action_default_deny(self) -> None:
        # Obtain valid request_id and csrf
        res = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "state": "default_deny_state",
            },
        )
        self.assertEqual(res.status_code, 200)
        cookie_header = res.headers.get("set-cookie", "")
        csrf_val = cookie_header.split("mh_csrf=")[1].split(";")[0]

        import re
        req_id_m = re.search(r'name="request_id"\s+value="([^"]+)"', res.text)
        self.assertIsNotNone(req_id_m)
        assert req_id_m is not None
        req_id = req_id_m.group(1)

        # POST without action (or with unrecognized action)
        res_dec = self.client.post(
            "/authorize/decision",
            data={
                "request_id": req_id,
                "csrf": csrf_val,
                "password": "correct-horse-battery-staple-long",
                "action": "something_unknown",
            },
            headers={"Cookie": f"mh_csrf={csrf_val}"},
            follow_redirects=False,
        )
        self.assertEqual(res_dec.status_code, 302)
        loc = res_dec.headers.get("location", "")
        parsed = urllib.parse.urlsplit(loc)
        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs.get("error"), ["access_denied"])
        self.assertEqual(qs.get("state"), ["default_deny_state"])
        self.assertEqual(qs.get("iss"), [self.config.issuer])

    def test_consent_and_error_pages_mobile_meta_and_html_lang(self) -> None:
        # Consent page
        res = self.client.get(
            "/authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.claude_redirect,
                "response_type": "code",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
        )
        self.assertIn('<html lang="en">', res.text)
        self.assertIn('<meta name="viewport" content="width=device-width, initial-scale=1">', res.text)
        self.assertIn('min-height: 44px', res.text)
        self.assertIn('font-size: 16px', res.text)

        # Error page
        res_err = self.client.get("/authorize?client_id=nonexistent")
        self.assertIn('<html lang="en">', res_err.text)
        self.assertIn('<meta name="viewport" content="width=device-width, initial-scale=1">', res_err.text)

        # Meta-refresh page
        from mindhub_oauth.consent import render_meta_refresh_response
        res_meta = render_meta_refresh_response("https://claude.ai/callback")
        body_meta = res_meta.body.decode("utf-8")
        self.assertIn('<html lang="en">', body_meta)
        self.assertIn('<meta name="viewport" content="width=device-width, initial-scale=1">', body_meta)

    def test_f2_duplicate_param_bounded_error(self) -> None:
        from mindhub_oauth.routes import FormParseError, parse_form_urlencoded, parse_query_params
        large_k = "x" * 10240
        with self.assertRaises(FormParseError) as cm:
            parse_query_params(f"{large_k}=1&{large_k}=2", self.config.resource)
        self.assertLessEqual(len(cm.exception.description), 128)
        self.assertIn("x" * 64, cm.exception.description)
        self.assertNotIn("x" * 65, cm.exception.description)

        non_ascii_k = "bad\x00\x1f\x7f\xff_" + ("y" * 100)
        with self.assertRaises(FormParseError) as cm2:
            parse_form_urlencoded(f"{non_ascii_k}=1&{non_ascii_k}=2".encode("utf-8"), self.config.resource)
        self.assertLessEqual(len(cm2.exception.description), 128)
        self.assertIn("?", cm2.exception.description)
        self.assertNotIn("y" * 65, cm2.exception.description)


if __name__ == "__main__":
    unittest.main()
