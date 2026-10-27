"""Unit tests for mindhub_oauth.config."""
from __future__ import annotations

import unittest

from mindhub_oauth.config import Config, ConfigError


def valid_env() -> dict[str, str]:
    return {
        "FACADE_PUBLIC_URL": "https://mindhub.example.com",
        "MINDHUB_UPSTREAM_API_KEY": "super-secret-mindhub-upstream-key-1234",
        "FACADE_OWNER_PASSWORD_HASH": "scrypt$32768$8$1$c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=$aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
        "FACADE_DB_PATH": "/tmp/oauth.db",
    }


class TestOAuthConfig(unittest.TestCase):
    def test_valid_minimal_config(self) -> None:
        cfg = Config.from_env(valid_env())
        self.assertEqual(cfg.public_url, "https://mindhub.example.com")
        self.assertEqual(cfg.issuer, "https://mindhub.example.com")
        self.assertEqual(cfg.resource, "https://mindhub.example.com/mcp")
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8089)
        self.assertEqual(cfg.upstream_url, "http://127.0.0.1:8088/mcp")
        self.assertEqual(cfg.db_path, "/tmp/oauth.db")
        self.assertEqual(cfg.max_scope, frozenset(["mindhub:read"]))
        self.assertEqual(cfg.default_scope, frozenset(["mindhub:read"]))
        self.assertEqual(cfg.access_ttl_seconds, 900)
        self.assertEqual(cfg.refresh_ttl_seconds, 2592000)
        self.assertEqual(cfg.code_ttl_seconds, 60)
        self.assertEqual(cfg.max_clients, 50)
        self.assertEqual(cfg.extra_redirect_uris, ())
        self.assertTrue(cfg.trust_cf_headers)
        self.assertTrue(cfg.google_meta_refresh)

    def test_custom_config_options(self) -> None:
        env = valid_env()
        env["FACADE_EXTRA_REDIRECT_URIS"] = (
            "https://app1.example.com/callback, https://app2.example.com/callback"
        )
        env["FACADE_MAX_CLIENTS"] = "100"
        env["FACADE_TRUST_CF_HEADERS"] = "0"
        env["FACADE_GOOGLE_META_REFRESH"] = "0"
        env["FACADE_CODE_TTL_SECONDS"] = "45"
        env["FACADE_REFRESH_TTL_SECONDS"] = "100000"
        env["FACADE_ACCESS_TTL_SECONDS"] = "1200"

        cfg = Config.from_env(env)
        self.assertEqual(
            cfg.extra_redirect_uris,
            ("https://app1.example.com/callback", "https://app2.example.com/callback"),
        )
        self.assertEqual(cfg.max_clients, 100)
        self.assertFalse(cfg.trust_cf_headers)
        self.assertFalse(cfg.google_meta_refresh)
        self.assertEqual(cfg.code_ttl_seconds, 45)
        self.assertEqual(cfg.refresh_ttl_seconds, 100000)
        self.assertEqual(cfg.access_ttl_seconds, 1200)

    def test_missing_required_vars_fail_closed(self) -> None:
        required = ["FACADE_PUBLIC_URL", "MINDHUB_UPSTREAM_API_KEY", "FACADE_OWNER_PASSWORD_HASH"]
        for var in required:
            with self.subTest(missing=var):
                env = valid_env()
                secret_val = env[var]
                del env[var]
                with self.assertRaises(ConfigError) as ctx:
                    Config.from_env(env)
                # Ensure the exception message does not leak secret values
                self.assertNotIn(secret_val, str(ctx.exception))

    def test_non_https_public_url_rejected(self) -> None:
        env = valid_env()
        env["FACADE_PUBLIC_URL"] = "http://mindhub.example.com"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

    def test_insecure_local_allows_http(self) -> None:
        env = valid_env()
        env["FACADE_PUBLIC_URL"] = "http://127.0.0.1:8089"
        env["FACADE_ALLOW_INSECURE_LOCAL"] = "1"
        cfg = Config.from_env(env)
        self.assertEqual(cfg.public_url, "http://127.0.0.1:8089")

    def test_public_url_with_path_or_trailing_slash_rejected(self) -> None:
        bad_urls = [
            "https://mindhub.example.com/",
            "https://mindhub.example.com/oauth",
            "https://mindhub.example.com/oauth/",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                env = valid_env()
                env["FACADE_PUBLIC_URL"] = url
                with self.assertRaises(ConfigError):
                    Config.from_env(env)

    def test_public_url_with_query_or_fragment_rejected(self) -> None:
        bad_urls = [
            "https://mindhub.example.com?query=1",
            "https://mindhub.example.com#fragment",
            "https://user:pass@mindhub.example.com",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                env = valid_env()
                env["FACADE_PUBLIC_URL"] = url
                with self.assertRaises(ConfigError):
                    Config.from_env(env)

    def test_non_loopback_upstream_rejected(self) -> None:
        bad_upstreams = [
            "http://192.168.1.100:8088/mcp",
            "https://127.0.0.1:8088/mcp",  # must be http
            "http://external.domain.com/mcp",
        ]
        for upstream in bad_upstreams:
            with self.subTest(upstream=upstream):
                env = valid_env()
                env["FACADE_UPSTREAM_URL"] = upstream
                with self.assertRaises(ConfigError):
                    Config.from_env(env)

    def test_non_loopback_bind_rejected(self) -> None:
        bad_hosts = ["0.0.0.0", "192.168.1.50", "example.com"]
        for host in bad_hosts:
            with self.subTest(host=host):
                env = valid_env()
                env["FACADE_HOST"] = host
                with self.assertRaises(ConfigError):
                    Config.from_env(env)

        # But allowed with override
        env = valid_env()
        env["FACADE_HOST"] = "0.0.0.0"
        env["FACADE_ALLOW_NON_LOOPBACK_BIND"] = "1"
        cfg = Config.from_env(env)
        self.assertEqual(cfg.host, "0.0.0.0")

    def test_repr_contains_no_secrets(self) -> None:
        env = valid_env()
        cfg = Config.from_env(env)
        cfg_repr = repr(cfg)
        self.assertNotIn(env["MINDHUB_UPSTREAM_API_KEY"], cfg_repr)
        self.assertNotIn(env["FACADE_OWNER_PASSWORD_HASH"], cfg_repr)
        self.assertIn("REDACTED", cfg_repr)
        self.assertIn("Config", cfg_repr)

    def test_default_scope_must_be_subset_of_max_scope(self) -> None:
        env = valid_env()
        env["FACADE_MAX_SCOPE"] = "mindhub:read"
        env["FACADE_DEFAULT_SCOPE"] = "mindhub:read mindhub:write"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

        # Valid subset
        env["FACADE_MAX_SCOPE"] = "mindhub:read mindhub:write"
        env["FACADE_DEFAULT_SCOPE"] = "mindhub:read"
        cfg = Config.from_env(env)
        self.assertEqual(cfg.default_scope, frozenset(["mindhub:read"]))
        self.assertEqual(cfg.max_scope, frozenset(["mindhub:read", "mindhub:write"]))

    def test_invalid_password_hash_format_rejected(self) -> None:
        bad_hashes = [
            "plainpassword",
            "argon2$32768$8$1$salt$hash",
            "scrypt$invalid$8$1$salt$hash",
            "scrypt$32768$8$1$missing_parts",
        ]
        for bad in bad_hashes:
            with self.subTest(bad=bad):
                env = valid_env()
                env["FACADE_OWNER_PASSWORD_HASH"] = bad
                with self.assertRaises(ConfigError):
                    Config.from_env(env)

    def test_ttl_bounds(self) -> None:
        # access ttl max 3600
        env = valid_env()
        env["FACADE_ACCESS_TTL_SECONDS"] = "3601"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

        # code ttl max 120
        env = valid_env()
        env["FACADE_CODE_TTL_SECONDS"] = "121"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

    def test_p7_facade_host_testserver_rejected_by_default_allowed_with_insecure_local(self) -> None:
        env = valid_env()
        env["FACADE_HOST"] = "testserver"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

        env["FACADE_ALLOW_INSECURE_LOCAL"] = "1"
        cfg = Config.from_env(env)
        self.assertEqual(cfg.host, "testserver")

    def test_p7_facade_upstream_url_testserver_rejected_by_default_allowed_with_insecure_local(self) -> None:
        env = valid_env()
        env["FACADE_UPSTREAM_URL"] = "http://testserver:8088/mcp"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

        env["FACADE_ALLOW_INSECURE_LOCAL"] = "1"
        cfg = Config.from_env(env)
        self.assertEqual(cfg.upstream_url, "http://testserver:8088/mcp")

    def test_p7_is_loopback_host_validation(self) -> None:
        from mindhub_oauth.config import is_loopback_host
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("127.0.0.2"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("[::1]"))
        self.assertFalse(is_loopback_host("testserver", allow_insecure_local=False))
        self.assertTrue(is_loopback_host("testserver", allow_insecure_local=True))
        self.assertFalse(is_loopback_host("192.168.1.1"))
        self.assertFalse(is_loopback_host("example.com"))

    def test_p8_scrypt_parameter_validation_bounds(self) -> None:
        import base64
        salt32 = base64.b64encode(b"s" * 32).decode()
        salt16 = base64.b64encode(b"s" * 16).decode()
        salt15 = base64.b64encode(b"s" * 15).decode()
        key32 = base64.b64encode(b"k" * 32).decode()
        key16 = base64.b64encode(b"k" * 16).decode()

        # Valid boundaries
        for n, r, p, s, k in [
            (16384, 1, 1, salt16, key32),
            (16384, 16, 1, salt32, key32),
            (32768, 8, 1, salt32, key32),
        ]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt${n}${r}${p}${s}${k}"
            cfg = Config.from_env(env)
            self.assertEqual(cfg.owner_password_hash, f"scrypt${n}${r}${p}${s}${k}")

        # Invalid: N not a power of 2
        for bad_n in [16385, 30000, 8192, 262144]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt${bad_n}$8$1${salt32}${key32}"
            with self.assertRaises(ConfigError):
                Config.from_env(env)

        # Invalid: r out of bounds (1 <= r <= 16)
        for bad_r in [0, 17]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt$32768${bad_r}$1${salt32}${key32}"
            with self.assertRaises(ConfigError):
                Config.from_env(env)

        # Invalid: p out of bounds (1 <= p <= 4)
        for bad_p in [0, 5]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt$32768$8${bad_p}${salt32}${key32}"
            with self.assertRaises(ConfigError):
                Config.from_env(env)

        # Invalid: salt < 16 bytes
        env = valid_env()
        env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt$32768$8$1${salt15}${key32}"
        with self.assertRaises(ConfigError):
            Config.from_env(env)

        # Invalid: key != 32 bytes
        env = valid_env()
        env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt$32768$8$1${salt32}${key16}"
        with self.assertRaises(ConfigError):
            Config.from_env(env)


        # Invalid: memory exceeds SCRYPT_MAXMEM (R1)
        for bad_n, bad_r, bad_p in [(65536, 8, 1), (32768, 16, 1), (131072, 16, 4)]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt${bad_n}${bad_r}${bad_p}${salt32}${key32}"
            with self.assertRaises(ConfigError):
                Config.from_env(env)

    def test_r1_scrypt_computable_by_real_scrypt(self) -> None:
        import base64
        import hashlib
        from mindhub_oauth.security import SCRYPT_MAXMEM

        salt32 = base64.b64encode(b"s" * 32).decode()
        key32 = base64.b64encode(b"k" * 32).decode()

        # Boundary tuples accepted by Config.from_env
        accepted_tuples = [
            (16384, 1, 1),
            (16384, 16, 1),
            (16384, 8, 4),
            (32768, 1, 1),
            (32768, 8, 1),
            (32768, 8, 2),
        ]
        for n, r, p in accepted_tuples:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt${n}${r}${p}${salt32}${key32}"
            cfg = Config.from_env(env)
            self.assertEqual(cfg.owner_password_hash, f"scrypt${n}${r}${p}${salt32}${key32}")

            # Must be computable by REAL hashlib.scrypt call with SCRYPT_MAXMEM
            derived = hashlib.scrypt(
                b"test-password",
                salt=b"s" * 32,
                n=n,
                r=r,
                p=p,
                maxmem=SCRYPT_MAXMEM,
                dklen=32,
            )
            self.assertEqual(len(derived), 32)

        # Specifically rejected tuples that exceed SCRYPT_MAXMEM
        for bad_n, bad_r, bad_p in [(65536, 8, 1), (32768, 16, 1), (131072, 16, 4)]:
            env = valid_env()
            env["FACADE_OWNER_PASSWORD_HASH"] = f"scrypt${bad_n}${bad_r}${bad_p}${salt32}${key32}"
            with self.assertRaises(ConfigError):
                Config.from_env(env)

    def test_r11_relative_db_path_rejected(self) -> None:
        for bad_path in ["oauth.db", "./oauth.db", "data/oauth.db"]:
            env = valid_env()
            env["FACADE_DB_PATH"] = bad_path
            with self.assertRaises(ConfigError):
                Config.from_env(env)

    def test_r11_allow_insecure_local_permits_relative_db_and_emits_warning(self) -> None:
        env = valid_env()
        env["FACADE_ALLOW_INSECURE_LOCAL"] = "1"
        env["FACADE_DB_PATH"] = "relative_oauth.db"
        with self.assertLogs("mindhub_oauth.config", level="WARNING") as cm:
            cfg = Config.from_env(env)
            self.assertEqual(cfg.db_path, "relative_oauth.db")
            self.assertTrue(any("FACADE_ALLOW_INSECURE_LOCAL is enabled" in line for line in cm.output))
            # Verify no secrets in warning
            for line in cm.output:
                self.assertNotIn("secret", line.lower())
                self.assertNotIn("password", line.lower())
                self.assertNotIn(env["FACADE_OWNER_PASSWORD_HASH"], line)


if __name__ == "__main__":
    unittest.main()
