"""Unit tests for mindhub_oauth.store."""
from __future__ import annotations

import concurrent.futures
import os
import tempfile
import unittest

from mindhub_oauth.store import OAuthStore


class TestOAuthStore(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_oauth.db")
        self.current_time = 1000.0
        self.store = OAuthStore(self.db_path, now_fn=lambda: self.current_time)

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def test_schema_initialization_and_indexes(self) -> None:
        with self.store.connection() as conn:
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            self.assertIn("clients", tables)
            self.assertIn("pending_authorizations", tables)
            self.assertIn("auth_codes", tables)
            self.assertIn("tokens", tables)
            self.assertIn("audit", tables)

            indexes = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                ).fetchall()
            ]
            self.assertIn("idx_tokens_family", indexes)
            self.assertIn("idx_auth_codes_family", indexes)

    def test_client_lifecycle(self) -> None:
        self.assertEqual(self.store.count_active_clients(), 0)

        client = self.store.create_client(
            client_id="client_1",
            client_name="Test App",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code", "refresh_token"],
        )
        self.assertEqual(client.client_id, "client_1")
        self.assertEqual(client.client_name, "Test App")
        self.assertEqual(self.store.count_active_clients(), 1)

        fetched = self.store.get_client("client_1")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.redirect_uris, ("https://claude.ai/api/mcp/auth_callback",))

        # Touch client
        self.current_time = 1100.0
        self.store.touch_client("client_1")
        updated = self.store.get_client("client_1")
        self.assertEqual(updated.last_used_at, 1100.0)

        # Revoke client
        self.store.revoke_client("client_1")
        self.assertIsNone(self.store.get_client("client_1"))
        self.assertEqual(self.store.count_active_clients(), 0)
        self.assertIsNotNone(self.store.get_client_include_revoked("client_1"))

    def test_pending_authorization_lifecycle(self) -> None:
        self.store.create_pending_authorization(
            request_id="req_123",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            state="state_xyz",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            csrf="csrf_secret_abc",
            ttl_seconds=600,
        )

        # Wrong CSRF fails
        consumed_bad = self.store.consume_pending_authorization("req_123", "wrong_csrf")
        self.assertIsNone(consumed_bad)

        # Correct CSRF succeeds
        consumed = self.store.consume_pending_authorization("req_123", "csrf_secret_abc")
        self.assertIsNotNone(consumed)
        self.assertEqual(consumed.client_id, "client_1")
        self.assertEqual(consumed.state, "state_xyz")

        # Second consume fails (single-use)
        consumed_again = self.store.consume_pending_authorization("req_123", "csrf_secret_abc")
        self.assertIsNone(consumed_again)

    def test_pending_authorization_expired(self) -> None:
        self.store.create_pending_authorization(
            request_id="req_exp",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            state=None,
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            csrf="csrf_exp",
            ttl_seconds=600,
        )
        # Advance time past 600s
        self.current_time = 1700.0
        consumed = self.store.consume_pending_authorization("req_exp", "csrf_exp")
        self.assertIsNone(consumed)

    def test_auth_code_lifecycle_and_replay_revokes_family(self) -> None:
        family_id = "family_fam1"
        self.store.create_auth_code(
            code="code_secret_xyz",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=60,
        )

        # Issue tokens in this family
        self.store.create_token(
            token="access_tok_1",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=900,
        )
        self.store.create_token(
            token="refresh_tok_1",
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=2592000,
        )

        # First consume succeeds
        rec, is_replay = self.store.consume_auth_code(
            code="code_secret_xyz",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
        )
        self.assertIsNotNone(rec)
        self.assertFalse(is_replay)
        self.assertEqual(rec.family_id, family_id)

        # Tokens in family are still active
        self.assertIsNotNone(self.store.get_access_token("access_tok_1"))

        # Replay consume fails, flags replay, and revokes whole family!
        rec2, is_replay2 = self.store.consume_auth_code(
            code="code_secret_xyz",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
        )
        self.assertIsNone(rec2)
        self.assertTrue(is_replay2)

        # Tokens in family are now REVOKED
        self.assertIsNone(self.store.get_access_token("access_tok_1"))

        # Audit event recorded
        audit_events = self.store.get_audit_events()
        self.assertTrue(any(e.event == "auth_code_reuse" and e.client_id == "client_1" for e in audit_events))

    def test_auth_code_expired_does_not_revoke_family(self) -> None:
        family_id = "family_exp"
        self.store.create_auth_code(
            code="code_will_expire",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=60,
        )
        self.store.create_token(
            token="access_tok_fam_exp",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=900,
        )

        # Advance time past 60s
        self.current_time = 1070.0
        rec, is_replay = self.store.consume_auth_code(
            code="code_will_expire",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
        )
        self.assertIsNone(rec)
        self.assertFalse(is_replay)

        # Family tokens must NOT be revoked!
        self.assertIsNotNone(self.store.get_access_token("access_tok_fam_exp"))
        audit_events = self.store.get_audit_events()
        self.assertFalse(any(e.event == "auth_code_reuse" for e in audit_events))

    def test_refresh_token_expired_does_not_revoke_family(self) -> None:
        family_id = "family_rf_exp"
        self.store.create_token(
            token="rf_will_expire",
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=100,
        )
        self.store.create_token(
            token="acc_rf_exp",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=900,
        )

        # Advance time past 100s
        self.current_time = 1150.0
        rec, is_replay = self.store.consume_refresh_token("rf_will_expire", client_id="client_1")
        self.assertIsNone(rec)
        self.assertFalse(is_replay)

        # Family tokens must NOT be revoked!
        self.assertIsNotNone(self.store.get_access_token("acc_rf_exp"))
        audit_events = self.store.get_audit_events()
        self.assertFalse(any(e.event == "refresh_token_reuse" for e in audit_events))

    def test_auth_code_mismatch_client_or_redirect(self) -> None:
        self.store.create_auth_code(
            code="code_mismatch",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_mismatch",
            ttl_seconds=60,
        )
        # Wrong client
        rec, is_replay = self.store.consume_auth_code(
            code="code_mismatch",
            client_id="wrong_client",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
        )
        self.assertIsNone(rec)
        self.assertFalse(is_replay)

    def test_token_lifecycle_access_and_refresh(self) -> None:
        family_id = "family_tokens"
        self.store.create_token(
            token="access_1",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=900,
        )
        self.store.create_token(
            token="refresh_1",
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id=family_id,
            ttl_seconds=2592000,
        )

        # Access token lookup
        acc = self.store.get_access_token("access_1")
        self.assertIsNotNone(acc)
        self.assertEqual(acc.scope, "mindhub:read")

        # Refresh token rotation (first consume succeeds)
        rf, is_replay = self.store.consume_refresh_token("refresh_1", client_id="client_1")
        self.assertIsNotNone(rf)
        self.assertFalse(is_replay)

        # Refresh token replay revokes family!
        rf2, is_replay2 = self.store.consume_refresh_token("refresh_1", client_id="client_1")
        self.assertIsNone(rf2)
        self.assertTrue(is_replay2)

        # Access token revoked
        self.assertIsNone(self.store.get_access_token("access_1"))

    def test_atomic_concurrency_threads(self) -> None:
        self.store.create_auth_code(
            code="concurrent_code",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_concurrent",
            ttl_seconds=60,
        )

        successes: list[bool] = []

        def attempt_consume():
            rec, _ = self.store.consume_auth_code(
                code="concurrent_code",
                client_id="client_1",
                redirect_uri="https://claude.ai/api/mcp/auth_callback",
            )
            return rec is not None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(attempt_consume) for _ in range(10)]
            for fut in concurrent.futures.as_completed(futures):
                if fut.result():
                    successes.append(True)

        # Exactly ONE thread must succeed
        self.assertEqual(len(successes), 1)

    def test_purge_expired(self) -> None:
        self.store.create_pending_authorization(
            request_id="purge_req",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            state=None,
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            csrf="csrf_val",
            ttl_seconds=10,
        )
        self.store.create_auth_code(
            code="purge_code",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_purge",
            ttl_seconds=10,
        )

        # Advance time by 100 seconds (code was unused: used=0)
        self.current_time = 1100.0
        self.store.purge_expired(force=True)

        with self.store.connection() as conn:
            pending_count = conn.execute("SELECT COUNT(*) FROM pending_authorizations").fetchone()[0]
            code_count = conn.execute("SELECT COUNT(*) FROM auth_codes").fetchone()[0]
            self.assertEqual(pending_count, 0)
            self.assertEqual(code_count, 0)

    def test_purge_used_auth_codes_retained_until_30_days(self) -> None:
        # Item A: used auth codes must not be deleted while their family could be alive
        self.store.create_auth_code(
            code="code_used_keep",
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_used_retention",
            ttl_seconds=60,
        )
        self.store.create_token(
            token="acc_live_family",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_used_retention",
            ttl_seconds=900,
        )
        # Consume code (so used=1)
        rec, is_replay = self.store.consume_auth_code("code_used_keep")
        self.assertIsNotNone(rec)
        self.assertFalse(is_replay)

        # Advance clock by 10 minutes (600s): expires_at (60s) has passed, but it's used
        self.current_time += 600.0
        self.store.purge_expired(force=True)

        # Replay the code => must be flagged as replay, revoke family, write audit event!
        rec_replay, is_replay2 = self.store.consume_auth_code("code_used_keep")
        self.assertIsNone(rec_replay)
        self.assertTrue(is_replay2)
        self.assertIsNone(self.store.get_access_token("acc_live_family"))
        events = self.store.get_audit_events()
        self.assertTrue(any(e.event == "auth_code_reuse" for e in events))

        # Advance clock past 30 days (30 * 86400s)
        self.current_time += 30 * 86400.0 + 10.0
        self.store.purge_expired(force=True)
        with self.store.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM auth_codes WHERE family_id='fam_used_retention'").fetchone()[0]
            self.assertEqual(row, 0)

    def test_purge_tokens_past_1_day_grace(self) -> None:
        # Item J: tokens deleted only when expires_at < now - 1 day (86400s)
        self.store.create_token(
            token="acc_exp_grace",
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_grace",
            ttl_seconds=100,
        )
        self.store.create_token(
            token="ref_exp_grace",
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_grace",
            ttl_seconds=100,
        )

        # Advance time by 200s (expired 100s ago, well within 1-day grace)
        self.current_time += 200.0
        self.store.purge_expired(force=True)

        with self.store.connection() as conn:
            tok_count = conn.execute("SELECT COUNT(*) FROM tokens WHERE family_id='fam_grace'").fetchone()[0]
            self.assertEqual(tok_count, 2)

        # Advance past 1 day (86400s)
        self.current_time += 86400.0 + 10.0
        self.store.purge_expired(force=True)

        with self.store.connection() as conn:
            tok_count = conn.execute("SELECT COUNT(*) FROM tokens WHERE family_id='fam_grace'").fetchone()[0]
            self.assertEqual(tok_count, 0)

    def test_purge_audit_rows_older_than_90_days(self) -> None:
        # Item E: purge audit rows older than 90 days (7,776,000s)
        self.store.log_audit("old_event", client_id="c1", detail="event from 91 days ago")
        self.current_time += 91 * 86400.0
        self.store.log_audit("recent_event", client_id="c1", detail="recent event")
        self.store.purge_expired(force=True)

        events = self.store.get_audit_events()
        self.assertFalse(any(e.event == "old_event" for e in events))
        self.assertTrue(any(e.event == "recent_event" for e in events))

    def test_client_lifecycle_stale_purge(self) -> None:
        # Item C: stale clients purge and active counting
        c_stale = self.store.create_client(
            client_id="c_stale_1",
            client_name="Stale App",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        c_active = self.store.create_client(
            client_id="c_active_with_token",
            client_name="Active App",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        # Give c_active an active token (e.g. refresh token with 30-day ttl)
        self.store.create_token(
            token="tok_active_c",
            kind="refresh",
            client_id="c_active_with_token",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_c",
            ttl_seconds=2592000,
        )

        # Advance clock by 25 hours (86400s + 3600s)
        self.current_time += 25 * 3600.0
        self.store.purge_expired(force=True)

        # c_stale must be deleted; c_active must remain!
        self.assertIsNone(self.store.get_client("c_stale_1"))
        self.assertIsNotNone(self.store.get_client("c_active_with_token"))
        # Stale client purged -> active count decreased from 2 to 1 (frees a slot)
        self.assertEqual(self.store.count_active_clients(), 1)

    def test_peek_refresh_token_non_consuming(self) -> None:
        # Item D: peek_refresh_token must not mark used or revoke
        self.store.create_token(
            token="peek_rf_tok",
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_peek",
            ttl_seconds=2592000,
        )
        rec = self.store.peek_refresh_token("peek_rf_tok")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.client_id, "client_1")
        self.assertFalse(rec.used)
        self.assertFalse(rec.revoked)

        # Still valid and not consumed
        rec2 = self.store.peek_refresh_token("peek_rf_tok")
        self.assertIsNotNone(rec2)
        self.assertFalse(rec2.used)

    def test_no_plaintext_secrets_stored(self) -> None:
        client_secret = "client_secret_xyz123"
        req_id = "req_secret_456"
        csrf = "csrf_secret_789"
        code = "code_secret_abc"
        access_tok = "access_token_secret_def"
        refresh_tok = "refresh_token_secret_ghi"

        self.store.create_pending_authorization(
            request_id=req_id,
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            state=None,
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            csrf=csrf,
            ttl_seconds=600,
        )
        self.store.create_auth_code(
            code=code,
            client_id="client_1",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_plain",
            ttl_seconds=60,
        )
        self.store.create_token(
            token=access_tok,
            kind="access",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_plain",
            ttl_seconds=900,
        )
        self.store.create_token(
            token=refresh_tok,
            kind="refresh",
            client_id="client_1",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_plain",
            ttl_seconds=2592000,
        )

        all_text = self.store.scan_all_text_columns()
        for secret in [client_secret, req_id, csrf, code, access_tok, refresh_tok]:
            for text_val in all_text:
                self.assertNotIn(
                    secret,
                    text_val,
                    f"Plaintext secret {secret} leaked in DB column value: {text_val}",
                )

    def test_audit_detail_never_contains_secrets_or_full_uris(self) -> None:
        # Log several audit events
        self.store.log_audit("register_rejected", client_id="c1", detail="invalid_redirect:evil.com")
        self.store.log_audit("auth_code_reuse", client_id="c1", detail="family_revoked")
        self.store.log_audit("token_revoked", client_id="c1", detail="manual_revocation")

        events = self.store.get_audit_events()
        self.assertGreaterEqual(len(events), 3)

        with self.store.connection() as conn:
            rows = conn.execute("SELECT detail FROM audit WHERE detail IS NOT NULL").fetchall()
            for r in rows:
                detail = r[0]
                self.assertNotIn("https://", detail)
                self.assertNotIn("http://", detail)
                self.assertNotIn("secret", detail.lower())
                self.assertNotIn("password", detail.lower())
                self.assertNotIn("token", detail.lower())
                self.assertNotIn("verifier", detail.lower())

    def test_p10_db_file_created_with_mode_0600(self) -> None:
        import stat
        db_file = os.path.join(self.temp_dir.name, "mode_test.db")
        new_store = OAuthStore(db_file)
        try:
            st = os.stat(db_file)
            mode = st.st_mode & 0o777
            self.assertEqual(mode, 0o600, f"Expected 0600 mode on DB file, got {oct(mode)}")
        finally:
            new_store.close()

    def test_r3_audit_truncation_central(self) -> None:
        # 64 KiB client_id
        huge_client_id = "c" * 65536
        huge_event = "e" * 200
        detail_with_control = "hello\x00\x1fworld\x7f\x80" + ("d" * 500)
        self.store.log_audit(huge_event, client_id=huge_client_id, detail=detail_with_control)

        with self.store.connection() as conn:
            row = conn.execute("SELECT event, client_id, detail FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(row)
            event_val, cid_val, detail_val = row[0], row[1], row[2]
            self.assertLessEqual(len(event_val), 64)
            self.assertLessEqual(len(cid_val), 64)
            self.assertLessEqual(len(detail_val), 256)
            # Control characters and non-ASCII replaced with '?'
            self.assertNotIn("\x00", detail_val)
            self.assertNotIn("\x1f", detail_val)
            self.assertNotIn("\x7f", detail_val)
            self.assertNotIn("\x80", detail_val)
            self.assertTrue(all(32 <= ord(c) <= 126 for c in detail_val))

    def test_r3_audit_cap_50000_rows(self) -> None:
        # Fast bulk insert 60,000 rows
        with self.store.connection() as conn:
            conn.execute("DELETE FROM audit")
            conn.executemany(
                "INSERT INTO audit (ts, event, client_id, detail) VALUES (?, ?, ?, ?)",
                [(self.current_time, "bulk_event", "c1", "detail") for _ in range(60000)],
            )
            count_before = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            self.assertEqual(count_before, 60000)

        self.store.purge_expired(force=True)

        with self.store.connection() as conn:
            count_after = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            self.assertLessEqual(count_after, 50000)

    def test_r4_dcr_slot_exhaustion_and_1h_purge(self) -> None:
        # Create a never-authorized client and an authorized client
        self.store.create_client(
            client_id="never_auth_client",
            client_name="Never Auth",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        self.store.create_client(
            client_id="auth_client_with_token",
            client_name="Has Token",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            grant_types=["authorization_code"],
        )
        self.store.create_token(
            token="tok_for_auth_client",
            kind="refresh",
            client_id="auth_client_with_token",
            scope="mindhub:read",
            resource="https://mindhub.example.com/mcp",
            family_id="fam_r4",
            ttl_seconds=2592000,
        )

        self.assertEqual(self.store.count_active_clients(), 2)

        # Advance clock by 61 minutes (3660s)
        self.current_time += 3660.0

        # Never-authorized client must stop counting in count_active_clients
        self.assertEqual(self.store.count_active_clients(), 1)

        # Purge must remove the never-authorized client, but keep the authorized client
        self.store.purge_expired(force=True)
        self.assertIsNone(self.store.get_client("never_auth_client"))
        self.assertIsNotNone(self.store.get_client("auth_client_with_token"))

    def test_r11_preexisting_0644_db_becomes_0600(self) -> None:
        import stat
        db_file = os.path.join(self.temp_dir.name, "preexisting_0644.db")
        # Pre-create file with 0o644 permissions
        with open(db_file, "w") as f:
            f.write("")
        os.chmod(db_file, 0o644)
        self.assertEqual(os.stat(db_file).st_mode & 0o777, 0o644)

        # Connect with OAuthStore
        st = OAuthStore(db_file)
        try:
            mode = os.stat(db_file).st_mode & 0o777
            self.assertEqual(mode, 0o600, f"Expected 0600 mode on pre-existing DB file, got {oct(mode)}")
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()
