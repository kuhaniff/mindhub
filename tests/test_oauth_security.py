"""Unit tests for mindhub_oauth.security."""
from __future__ import annotations

import io
import sys
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mindhub_oauth._http import httpx
from mindhub_oauth.security import (
    compute_code_challenge,
    extract_client_ip,
    generate_secret,
    hash_password,
    is_loopback_ip,
    LockoutTracker,
    RateLimiter,
    validate_code_verifier,
    validate_redirect_uri,
    verify_password,
)


class TestOAuthSecurity(unittest.TestCase):
    def test_pkce_rfc7636_vector(self) -> None:
        # RFC 7636 Appendix B test vector
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        self.assertEqual(compute_code_challenge(verifier), expected_challenge)
        self.assertTrue(validate_code_verifier(verifier))

    def test_pkce_plain_rejected(self) -> None:
        # Code challenge generation only supports S256
        with self.assertRaises(ValueError):
            compute_code_challenge("any_verifier", method="plain")

    def test_code_verifier_validation(self) -> None:
        # 43-128 chars [A-Za-z0-9-._~]
        self.assertTrue(validate_code_verifier("a" * 43))
        self.assertTrue(validate_code_verifier("z" * 128))
        self.assertFalse(validate_code_verifier("a" * 42))  # too short
        self.assertFalse(validate_code_verifier("a" * 129))  # too long
        self.assertFalse(validate_code_verifier("a" * 42 + "@"))  # invalid char
        self.assertFalse(validate_code_verifier("a" * 42 + " "))  # space

    def test_scrypt_verify_ok_wrong_malformed(self) -> None:
        password = "correct-horse-battery-staple-long"
        phash = hash_password(password)
        self.assertTrue(phash.startswith("scrypt$32768$8$1$"))

        # Verify correct
        self.assertTrue(verify_password(password, phash))

        # Verify wrong password
        self.assertFalse(verify_password("wrong-password", phash))

        # Verify empty password
        self.assertFalse(verify_password("", phash))

        # Verify malformed hash string (must not crash, constant-time fallback)
        self.assertFalse(verify_password(password, "malformed_hash"))
        self.assertFalse(verify_password(password, "scrypt$invalid$8$1$salt$hash"))

    def test_decision_password_hash_with_malformed_format_still_takes_dummy_compute_path(self) -> None:
        import hashlib
        with patch.object(hashlib, "scrypt", wraps=hashlib.scrypt) as mock_scrypt:
            # Malformed hash format
            res1 = verify_password("some_pw", "not_a_valid_format")
            self.assertFalse(res1)
            self.assertGreaterEqual(mock_scrypt.call_count, 1)

            mock_scrypt.reset_mock()
            # Empty password
            res2 = verify_password("", "scrypt$invalid$8$1$salt$hash")
            self.assertFalse(res2)
            self.assertGreaterEqual(mock_scrypt.call_count, 1)

            mock_scrypt.reset_mock()
            # Non-scrypt prefix
            res3 = verify_password("some_pw", "bcrypt$32768$8$1$c2FsdA==$aGFzaA==")
            self.assertFalse(res3)
            self.assertGreaterEqual(mock_scrypt.call_count, 1)

    def test_p8_verify_password_propagates_memory_error(self) -> None:
        import hashlib
        phash = hash_password("correct-horse-battery-staple-long")
        with patch.object(hashlib, "scrypt", side_effect=MemoryError("Out of memory")):
            with self.assertRaises(MemoryError):
                verify_password("correct-horse-battery-staple-long", phash)

    def test_r1_verify_password_resource_failure_logs_error(self) -> None:
        # A well-formed scrypt hash whose parameters exceed SCRYPT_MAXMEM
        # N=65536, r=8, p=1 requires ~64.003 MiB which exceeds the 64 MiB limit
        salt_b64 = "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M="
        key_b64 = "aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg="
        exceed_hash = f"scrypt$65536$8$1${salt_b64}${key_b64}"
        with self.assertLogs("mindhub_oauth.security", level="ERROR") as cm:
            res = verify_password("secret-pw", exceed_hash)
            self.assertFalse(res)
            self.assertEqual(len(cm.output), 1)
            log_line = cm.output[0]
            self.assertIn("scrypt calculation failed", log_line)
            # Ensure no secret or hash or password leaked in log line
            self.assertNotIn("secret-pw", log_line)
            self.assertNotIn(salt_b64, log_line)
            self.assertNotIn(key_b64, log_line)

    def test_generate_secret_entropy(self) -> None:
        s1 = generate_secret()
        s2 = generate_secret()
        self.assertNotEqual(s1, s2)
        self.assertGreaterEqual(len(s1), 43)

    def test_r5_redirect_uri_invalid_ports(self) -> None:
        self.assertFalse(validate_redirect_uri("https://evil.com:99999/"))
        self.assertFalse(validate_redirect_uri("https://oauth-redirect.googleusercontent.com:abc/r/x"))

    def test_redirect_uri_allowlist(self) -> None:
        # Claude production URIs
        self.assertTrue(validate_redirect_uri("https://claude.ai/api/mcp/auth_callback"))
        self.assertTrue(validate_redirect_uri("https://claude.com/api/mcp/auth_callback"))

        # Google redirect relay URIs
        self.assertTrue(
            validate_redirect_uri(
                "https://oauth-redirect.googleusercontent.com/r/my-project-123"
            )
        )
        self.assertTrue(
            validate_redirect_uri(
                "https://oauth-redirect.googleusercontent.com/a/my-project-123"
            )
        )
        self.assertTrue(
            validate_redirect_uri(
                "https://oauth-redirect-sandbox.googleusercontent.com/r/my-project-123"
            )
        )
        self.assertTrue(
            validate_redirect_uri(
                "https://oauth-redirect-sandbox.googleusercontent.com/a/my-project-123"
            )
        )

        # Extra redirect URIs
        extra = ("https://custom.app.example.com/oauth/callback",)
        self.assertTrue(
            validate_redirect_uri(
                "https://custom.app.example.com/oauth/callback",
                extra_allowed=extra,
            )
        )

    def test_redirect_uri_rejections(self) -> None:
        disallowed = [
            # Insecure / scheme tricks
            "http://claude.ai/api/mcp/auth_callback",
            "javascript:alert(1)",
            "data:text/html,evil",
            # Path tricks & trailing slash
            "https://claude.ai/api/mcp/auth_callback/",
            "https://claude.ai/api/mcp/auth_callback/extra",
            "https://claude.ai/api/mcp/../evil",
            "https://claude.ai/api/mcp/%2e%2e/evil",
            # Host tricks & wildcards
            "https://claude.ai.evil.com/api/mcp/auth_callback",
            "https://evil.com/?https://claude.ai/api/mcp/auth_callback",
            "https://claude.ai@evil.com/api/mcp/auth_callback",
            "https://x.googleusercontent.com/r/a",
            "https://oauth-redirect-test.googleusercontent.com/r/a",
            "https://evil.googleusercontent.com/r/a",
            # Google path must be /r/ or /a/
            "https://oauth-redirect.googleusercontent.com/x/my-project",
            "https://oauth-redirect.googleusercontent.com/r",
            "https://oauth-redirect.googleusercontent.com/",
            # Query / fragment / port / userinfo / whitespace
            "https://claude.ai/api/mcp/auth_callback?foo=bar",
            "https://claude.ai/api/mcp/auth_callback#fragment",
            "https://claude.ai:443/api/mcp/auth_callback",
            "https://claude.ai:8443/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback ",
            "https://claude.ai/api/mcp/auth_callback\n",
            "https://localhost/callback",
            "https://127.0.0.1/callback",
        ]
        for uri in disallowed:
            with self.subTest(uri=uri):
                self.assertFalse(
                    validate_redirect_uri(uri),
                    f"Disallowed URI unexpectedly accepted: {uri}",
                )

    def test_rate_limiter(self) -> None:
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        now = 1000.0

        # First 3 requests allowed
        self.assertTrue(limiter.check("ip1", now_fn=lambda: now))
        self.assertTrue(limiter.check("ip1", now_fn=lambda: now))
        self.assertTrue(limiter.check("ip1", now_fn=lambda: now))

        # 4th request blocked
        self.assertFalse(limiter.check("ip1", now_fn=lambda: now))

        # Different IP allowed
        self.assertTrue(limiter.check("ip2", now_fn=lambda: now))

        # After window expires, allowed again
        now = 1061.0
        self.assertTrue(limiter.check("ip1", now_fn=lambda: now))

    def test_rate_limiter_memory_bounded(self) -> None:
        limiter = RateLimiter(max_requests=5, window_seconds=60, max_keys=10)
        now = 1000.0
        for i in range(15):
            self.assertTrue(limiter.check(f"ip_{i}", now_fn=lambda: now))
        self.assertLessEqual(len(limiter._hits), 10)
        # Advance time and prune
        now = 1061.0
        limiter.prune(now)
        self.assertEqual(len(limiter._hits), 0)

    def test_lockout_tracker_memory_bounded(self) -> None:
        tracker = LockoutTracker(max_failures=5, window_seconds=900, max_keys=10)
        now = 1000.0
        for i in range(15):
            tracker.record_failure(f"ip_{i}", now)
        self.assertLessEqual(len(tracker._failures), 10)
        # Advance time past window: is_locked removes expired history
        now = 2000.0
        self.assertFalse(tracker.is_locked("ip_14", now))
        self.assertNotIn("ip_14", tracker._failures)
        tracker.prune(now)
        self.assertEqual(len(tracker._failures), 0)

    def test_hash_password_cli_refuses_argv_and_enforces_rules(self) -> None:
        from mindhub_oauth.__main__ import main

        # Refuses password as argv
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", new_callable=io.StringIO):
                main(["hash-password", "my-secret-password-attempt"])

        # Rejects password shorter than 14 chars
        with patch("getpass.getpass", side_effect=["short123", "short123"]):
            with self.assertRaises(SystemExit):
                with patch("sys.stdout", new_callable=io.StringIO):
                    main(["hash-password"])

        # Rejects mismatched passwords
        with patch("getpass.getpass", side_effect=["longpassword1234", "differentpassword1234"]):
            with self.assertRaises(SystemExit):
                with patch("sys.stdout", new_callable=io.StringIO):
                    main(["hash-password"])

        # Success prints only the hash
        with patch("getpass.getpass", side_effect=["valid-long-password-1234", "valid-long-password-1234"]):
            stdout = io.StringIO()
            with patch("sys.stdout", stdout):
                main(["hash-password"])
            output = stdout.getvalue().strip()
            self.assertTrue(output.startswith("scrypt$32768$8$1$"))
            self.assertTrue(verify_password("valid-long-password-1234", output))


class TestExtractClientIp(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        async def ip_endpoint(request: Request):
            trust = request.query_params.get("trust", "1") == "1"
            ip = extract_client_ip(request, trust_cf_headers=trust)
            return PlainTextResponse(ip)

        self.app = Starlette(routes=[Route("/ip", ip_endpoint)])

    async def test_non_loopback_peer_with_spoofed_cf_header(self) -> None:
        transport = httpx.ASGITransport(app=self.app, client=("198.51.100.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.get("/ip", headers={"CF-Connecting-IP": "203.0.113.199"})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "198.51.100.1")

    async def test_loopback_peer_with_valid_cf_header(self) -> None:
        transport = httpx.ASGITransport(app=self.app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.get("/ip", headers={"CF-Connecting-IP": "203.0.113.199"})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "203.0.113.199")

    async def test_loopback_peer_with_malformed_cf_header_falls_back_to_peer(self) -> None:
        transport = httpx.ASGITransport(app=self.app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.get("/ip", headers={"CF-Connecting-IP": "not-a-valid-ip-address"})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "127.0.0.1")

    async def test_trust_flag_off_returns_peer_ip(self) -> None:
        transport = httpx.ASGITransport(app=self.app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.get("/ip?trust=0", headers={"CF-Connecting-IP": "203.0.113.199"})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "127.0.0.1")

    async def test_ipv6_loopback_peer_with_valid_cf_header(self) -> None:
        transport = httpx.ASGITransport(app=self.app, client=("::1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.get("/ip", headers={"CF-Connecting-IP": "203.0.113.199"})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "203.0.113.199")


if __name__ == "__main__":
    unittest.main()
