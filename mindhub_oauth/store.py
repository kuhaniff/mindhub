"""SQLite storage layer for Mindhub OAuth facade."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence


def sha256_hex(val: str) -> str:
    """Return SHA-256 hex digest of a string."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    client_name: str | None
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    created_at: float
    last_used_at: float
    revoked: bool


@dataclass(frozen=True)
class PendingAuthRecord:
    request_id_hash: str
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    scope: str
    resource: str
    csrf_hash: str
    created_at: float
    expires_at: float
    used: bool


@dataclass(frozen=True)
class AuthCodeRecord:
    code_hash: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    scope: str
    resource: str
    created_at: float
    expires_at: float
    used: bool
    family_id: str


@dataclass(frozen=True)
class TokenRecord:
    token_hash: str
    kind: str
    client_id: str
    scope: str
    resource: str
    family_id: str
    created_at: float
    expires_at: float
    revoked: bool
    used: bool


@dataclass(frozen=True)
class AuditEvent:
    id: int
    ts: float
    event: str
    client_id: str | None
    detail: str | None


def _sanitize_audit_text(val: str | None, max_len: int) -> str | None:
    if val is None:
        return None
    s = str(val)[:max_len]
    return "".join(c if (32 <= ord(c) <= 126) else "?" for c in s)


class OAuthStore:
    """Thread-safe SQLite store with atomic token rotation and family revocation."""

    def __init__(self, db_path: str, now_fn: Callable[[], float] | None = None) -> None:
        self._db_path = db_path
        self._now_fn = now_fn or time.time
        self._lock = threading.RLock()
        self._last_purge_at = 0.0

        old_umask = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                isolation_level=None,  # autocommit mode, transactions managed explicitly
            )
        finally:
            os.umask(old_umask)
        self._conn.row_factory = sqlite3.Row

        if os.path.isfile(self._db_path):
            try:
                os.chmod(self._db_path, 0o600)
            except OSError:
                pass

        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._create_schema()
            self.purge_expired(force=True)

    @property
    def now(self) -> float:
        return self._now_fn()

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            yield self._conn

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT,
                redirect_uris_json TEXT NOT NULL,
                grant_types_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_used_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pending_authorizations (
                request_id_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                state TEXT,
                code_challenge TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                csrf_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                family_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                kind TEXT CHECK (kind IN ('access', 'refresh')),
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                family_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                event TEXT NOT NULL,
                client_id TEXT,
                detail TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_clients_revoked ON clients(revoked);
            CREATE INDEX IF NOT EXISTS idx_pending_auth_exp ON pending_authorizations(expires_at);
            CREATE INDEX IF NOT EXISTS idx_pending_auth_used ON pending_authorizations(used);
            CREATE INDEX IF NOT EXISTS idx_auth_codes_exp ON auth_codes(expires_at);
            CREATE INDEX IF NOT EXISTS idx_auth_codes_family ON auth_codes(family_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_family ON tokens(family_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_exp ON tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(revoked);
            CREATE INDEX IF NOT EXISTS idx_tokens_client ON tokens(client_id);
            """
        )

    # -----------------------------------------------------------------------
    # Purge & Maintenance
    # -----------------------------------------------------------------------

    def purge_expired(self, force: bool = False) -> None:
        """Purge expired rows at most once per minute opportunistically."""
        with self._lock:
            now = self.now
            if not force and (now - self._last_purge_at < 60.0):
                return

            self._last_purge_at = now
            self._conn.execute("DELETE FROM pending_authorizations WHERE expires_at <= ?", (now,))
            # Auth codes: keep used codes for 30 days so replay attacks can still trigger family revocation
            self._conn.execute(
                """
                DELETE FROM auth_codes
                WHERE (used = 0 AND expires_at <= ?)
                   OR (used = 1 AND expires_at <= ?)
                """,
                (now, now - 30 * 86400.0),
            )
            # Tokens are kept for 1-day grace period past expiry for audit/rotation checks
            self._conn.execute("DELETE FROM tokens WHERE expires_at < ?", (now - 86400.0,))
            # Audit rows older than 90 days are purged, and audit table is capped at newest 50000 rows
            self._conn.execute("DELETE FROM audit WHERE ts < ?", (now - 90 * 86400.0,))
            self._conn.execute(
                "DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 50000)"
            )
            # Stale clients purge: revoked=0 with no tokens/codes/pending and unused > 1h,
            # or revoked=1 older than 30 days with no tokens
            self._conn.execute(
                """
                DELETE FROM clients
                WHERE (
                    revoked = 0
                    AND last_used_at < ?
                    AND client_id NOT IN (SELECT client_id FROM tokens)
                    AND client_id NOT IN (SELECT client_id FROM auth_codes)
                    AND client_id NOT IN (SELECT client_id FROM pending_authorizations)
                ) OR (
                    revoked = 1
                    AND (created_at < ? OR last_used_at < ?)
                    AND client_id NOT IN (SELECT client_id FROM tokens)
                )
                """,
                (now - 3600.0, now - 30 * 86400.0, now - 30 * 86400.0),
            )

    # -----------------------------------------------------------------------
    # Client Management
    # -----------------------------------------------------------------------

    def create_client(
        self,
        client_id: str,
        client_name: str | None,
        redirect_uris: Sequence[str],
        grant_types: Sequence[str],
    ) -> ClientRecord:
        with self._lock:
            self.purge_expired()
            now = self.now
            self._conn.execute(
                """
                INSERT INTO clients (
                    client_id, client_name, redirect_uris_json, grant_types_json,
                    created_at, last_used_at, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    client_id,
                    client_name,
                    json.dumps(list(redirect_uris)),
                    json.dumps(list(grant_types)),
                    now,
                    now,
                ),
            )
            return ClientRecord(
                client_id=client_id,
                client_name=client_name,
                redirect_uris=tuple(redirect_uris),
                grant_types=tuple(grant_types),
                created_at=now,
                last_used_at=now,
                revoked=False,
            )

    def get_client(self, client_id: str) -> ClientRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM clients WHERE client_id = ? AND revoked = 0",
                (client_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_client(row)

    def get_client_include_revoked(self, client_id: str) -> ClientRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_client(row)

    def count_active_clients(self) -> int:
        with self._lock:
            now = self.now
            row = self._conn.execute(
                """
                SELECT COUNT(*) FROM clients
                WHERE revoked = 0
                  AND (
                      client_id IN (SELECT client_id FROM tokens)
                      OR client_id IN (SELECT client_id FROM auth_codes)
                      OR client_id IN (SELECT client_id FROM pending_authorizations)
                      OR last_used_at >= ?
                  )
                """,
                (now - 3600.0,),
            ).fetchone()
            return int(row[0]) if row else 0

    def touch_client(self, client_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE clients SET last_used_at = ? WHERE client_id = ?",
                (self.now, client_id),
            )

    def revoke_client(self, client_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE clients SET revoked = 1 WHERE client_id = ?",
                (client_id,),
            )
            # Also revoke all active tokens for this client
            self._conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE client_id = ?",
                (client_id,),
            )

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> ClientRecord:
        return ClientRecord(
            client_id=row["client_id"],
            client_name=row["client_name"],
            redirect_uris=tuple(json.loads(row["redirect_uris_json"])),
            grant_types=tuple(json.loads(row["grant_types_json"])),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked=bool(row["revoked"]),
        )

    # -----------------------------------------------------------------------
    # Pending Authorization (Login / Consent)
    # -----------------------------------------------------------------------

    def create_pending_authorization(
        self,
        request_id: str,
        client_id: str,
        redirect_uri: str,
        state: str | None,
        code_challenge: str,
        scope: str,
        resource: str,
        csrf: str,
        ttl_seconds: int = 600,
    ) -> PendingAuthRecord:
        with self._lock:
            self.purge_expired()
            now = self.now
            expires_at = now + ttl_seconds
            req_hash = sha256_hex(request_id)
            csrf_h = sha256_hex(csrf)

            self._conn.execute(
                """
                INSERT INTO pending_authorizations (
                    request_id_hash, client_id, redirect_uri, state, code_challenge,
                    scope, resource, csrf_hash, created_at, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    req_hash,
                    client_id,
                    redirect_uri,
                    state,
                    code_challenge,
                    scope,
                    resource,
                    csrf_h,
                    now,
                    expires_at,
                ),
            )
            return PendingAuthRecord(
                request_id_hash=req_hash,
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=code_challenge,
                scope=scope,
                resource=resource,
                csrf_hash=csrf_h,
                created_at=now,
                expires_at=expires_at,
                used=False,
            )

    def get_pending_authorization(
        self, request_id: str, csrf: str
    ) -> PendingAuthRecord | None:
        """Validate pending authorization and CSRF without marking used."""
        with self._lock:
            self.purge_expired()
            now = self.now
            req_hash = sha256_hex(request_id)
            csrf_h = sha256_hex(csrf)

            row = self._conn.execute(
                "SELECT * FROM pending_authorizations WHERE request_id_hash = ?",
                (req_hash,),
            ).fetchone()
            if row is None or bool(row["used"]) or row["expires_at"] <= now:
                return None

            if not hmac.compare_digest(row["csrf_hash"], csrf_h):
                return None

            return PendingAuthRecord(
                request_id_hash=row["request_id_hash"],
                client_id=row["client_id"],
                redirect_uri=row["redirect_uri"],
                state=row["state"],
                code_challenge=row["code_challenge"],
                scope=row["scope"],
                resource=row["resource"],
                csrf_hash=row["csrf_hash"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                used=False,
            )

    def consume_pending_authorization(
        self, request_id: str, csrf: str
    ) -> PendingAuthRecord | None:
        """Atomically consume pending authorization and verify CSRF."""
        with self._lock:
            self.purge_expired()
            now = self.now
            req_hash = sha256_hex(request_id)
            csrf_h = sha256_hex(csrf)

            row = self._conn.execute(
                "SELECT * FROM pending_authorizations WHERE request_id_hash = ?",
                (req_hash,),
            ).fetchone()
            if row is None or bool(row["used"]) or row["expires_at"] <= now:
                return None

            # Constant-time comparison of CSRF hash
            if not hmac.compare_digest(row["csrf_hash"], csrf_h):
                return None

            # Atomic mark used
            cur = self._conn.execute(
                """
                UPDATE pending_authorizations
                SET used = 1
                WHERE request_id_hash = ? AND used = 0 AND expires_at > ?
                """,
                (req_hash, now),
            )
            if cur.rowcount != 1:
                return None

            return PendingAuthRecord(
                request_id_hash=row["request_id_hash"],
                client_id=row["client_id"],
                redirect_uri=row["redirect_uri"],
                state=row["state"],
                code_challenge=row["code_challenge"],
                scope=row["scope"],
                resource=row["resource"],
                csrf_hash=row["csrf_hash"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                used=True,
            )

    def count_active_pending_authorizations(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM pending_authorizations WHERE used = 0 AND expires_at > ?",
                (self.now,),
            ).fetchone()
            return int(row[0]) if row else 0

    # -----------------------------------------------------------------------
    # Authorization Codes
    # -----------------------------------------------------------------------

    def create_auth_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scope: str,
        resource: str,
        family_id: str,
        ttl_seconds: int = 60,
    ) -> AuthCodeRecord:
        with self._lock:
            self.purge_expired()
            self.touch_client(client_id)
            now = self.now
            expires_at = now + ttl_seconds
            code_h = sha256_hex(code)

            self._conn.execute(
                """
                INSERT INTO auth_codes (
                    code_hash, client_id, redirect_uri, code_challenge, scope,
                    resource, created_at, expires_at, used, family_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    code_h,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    scope,
                    resource,
                    now,
                    expires_at,
                    family_id,
                ),
            )
            return AuthCodeRecord(
                code_hash=code_h,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                scope=scope,
                resource=resource,
                created_at=now,
                expires_at=expires_at,
                used=False,
                family_id=family_id,
            )

    def consume_auth_code(
        self,
        code: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> tuple[AuthCodeRecord | None, bool]:
        """Atomically consume auth code.

        Returns (record, is_replay).
        If code was already used, revokes the whole family and returns (None, True).
        """
        with self._lock:
            self.purge_expired()
            now = self.now
            code_h = sha256_hex(code)

            row = self._conn.execute(
                "SELECT * FROM auth_codes WHERE code_hash = ?",
                (code_h,),
            ).fetchone()

            if row is None:
                return (None, False)

            rec = AuthCodeRecord(
                code_hash=row["code_hash"],
                client_id=row["client_id"],
                redirect_uri=row["redirect_uri"],
                code_challenge=row["code_challenge"],
                scope=row["scope"],
                resource=row["resource"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                used=bool(row["used"]),
                family_id=row["family_id"],
            )

            # Check for replay
            if rec.used:
                self.revoke_family(rec.family_id, reason="auth_code_reuse")
                self.log_audit("auth_code_reuse", client_id=rec.client_id, detail="family revoked")
                return (None, True)

            # Check expiry
            if rec.expires_at <= now:
                return (None, False)

            # Atomic single-use update
            cur = self._conn.execute(
                """
                UPDATE auth_codes
                SET used = 1
                WHERE code_hash = ? AND used = 0 AND expires_at > ?
                """,
                (code_h, now),
            )
            if cur.rowcount != 1:
                # Concurrent race consumed it: replay
                self.revoke_family(rec.family_id, reason="auth_code_reuse")
                self.log_audit("auth_code_reuse", client_id=rec.client_id, detail="family revoked")
                return (None, True)

            # Validate client_id and redirect_uri if supplied
            if client_id is not None and rec.client_id != client_id:
                return (None, False)
            if redirect_uri is not None and rec.redirect_uri != redirect_uri:
                return (None, False)

            return (rec, False)

    # -----------------------------------------------------------------------
    # Tokens (Access + Refresh)
    # -----------------------------------------------------------------------

    def create_token(
        self,
        token: str,
        kind: str,
        client_id: str,
        scope: str,
        resource: str,
        family_id: str,
        ttl_seconds: int,
    ) -> TokenRecord:
        with self._lock:
            self.purge_expired()
            self.touch_client(client_id)
            now = self.now
            expires_at = now + ttl_seconds
            tok_h = sha256_hex(token)

            self._conn.execute(
                """
                INSERT INTO tokens (
                    token_hash, kind, client_id, scope, resource, family_id,
                    created_at, expires_at, revoked, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    tok_h,
                    kind,
                    client_id,
                    scope,
                    resource,
                    family_id,
                    now,
                    expires_at,
                ),
            )
            return TokenRecord(
                token_hash=tok_h,
                kind=kind,
                client_id=client_id,
                scope=scope,
                resource=resource,
                family_id=family_id,
                created_at=now,
                expires_at=expires_at,
                revoked=False,
                used=False,
            )

    def get_access_token(self, token: str) -> TokenRecord | None:
        with self._lock:
            self.purge_expired()
            tok_h = sha256_hex(token)
            row = self._conn.execute(
                """
                SELECT * FROM tokens
                WHERE token_hash = ? AND kind = 'access' AND revoked = 0 AND expires_at > ?
                """,
                (tok_h, self.now),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_token(row)

    def peek_refresh_token(self, refresh_token: str) -> TokenRecord | None:
        """Lookup refresh token without consuming it or checking expiry/revocation."""
        with self._lock:
            self.purge_expired()
            tok_h = sha256_hex(refresh_token)
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE token_hash = ? AND kind = 'refresh'",
                (tok_h,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_token(row)

    def atomic_consume_refresh_token(self, refresh_token: str, family_id: str) -> bool:
        """Atomically mark a refresh token used. If race or replay, revoke family."""
        with self._lock:
            now = self.now
            tok_h = sha256_hex(refresh_token)
            cur = self._conn.execute(
                """
                UPDATE tokens
                SET used = 1
                WHERE token_hash = ? AND used = 0 AND revoked = 0 AND expires_at > ?
                """,
                (tok_h, now),
            )
            if cur.rowcount != 1:
                self.revoke_family(family_id, reason="refresh_token_reuse")
                self.log_audit("refresh_token_reuse", detail="family revoked")
                return False
            return True

    def consume_refresh_token(
        self, refresh_token: str, client_id: str | None = None
    ) -> tuple[TokenRecord | None, bool]:
        """Atomically consume refresh token for rotation.

        Returns (record, is_replay).
        If token was already used or revoked, revokes the whole family.
        """
        with self._lock:
            self.purge_expired()
            now = self.now
            tok_h = sha256_hex(refresh_token)

            row = self._conn.execute(
                "SELECT * FROM tokens WHERE token_hash = ? AND kind = 'refresh'",
                (tok_h,),
            ).fetchone()

            if row is None:
                return (None, False)

            rec = self._row_to_token(row)

            # Check replay or revoked
            if rec.used or rec.revoked:
                self.revoke_family(rec.family_id, reason="refresh_token_reuse")
                self.log_audit("refresh_token_reuse", client_id=rec.client_id, detail="family revoked")
                return (None, True)

            # Check expiry
            if rec.expires_at <= now:
                return (None, False)

            # Atomic mark used
            cur = self._conn.execute(
                """
                UPDATE tokens
                SET used = 1
                WHERE token_hash = ? AND used = 0 AND revoked = 0 AND expires_at > ?
                """,
                (tok_h, now),
            )
            if cur.rowcount != 1:
                self.revoke_family(rec.family_id, reason="refresh_token_reuse")
                self.log_audit("refresh_token_reuse", client_id=rec.client_id, detail="family revoked")
                return (None, True)

            if client_id is not None and rec.client_id != client_id:
                return (None, False)

            return (rec, False)

    def revoke_family(self, family_id: str, reason: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE family_id = ?",
                (family_id,),
            )

    def revoke_token(self, token: str, client_id: str | None = None) -> bool:
        with self._lock:
            if not client_id:
                return False
            tok_h = sha256_hex(token)
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE token_hash = ?",
                (tok_h,),
            ).fetchone()
            if row is None:
                return False

            if row["client_id"] != client_id:
                return False

            if row["kind"] == "refresh":
                self.revoke_family(row["family_id"], reason="token_revocation")
            else:
                self._conn.execute(
                    "UPDATE tokens SET revoked = 1 WHERE token_hash = ?",
                    (tok_h,),
                )
            return True

    @staticmethod
    def _row_to_token(row: sqlite3.Row) -> TokenRecord:
        return TokenRecord(
            token_hash=row["token_hash"],
            kind=row["kind"],
            client_id=row["client_id"],
            scope=row["scope"],
            resource=row["resource"],
            family_id=row["family_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked=bool(row["revoked"]),
            used=bool(row["used"]),
        )

    # -----------------------------------------------------------------------
    # Audit Logging
    # -----------------------------------------------------------------------

    def log_audit(
        self, event: str, client_id: str | None = None, detail: str | None = None
    ) -> None:
        with self._lock:
            safe_event = _sanitize_audit_text(event, 64) or ""
            safe_client_id = _sanitize_audit_text(client_id, 64)
            safe_detail = _sanitize_audit_text(detail, 256)
            self._conn.execute(
                "INSERT INTO audit (ts, event, client_id, detail) VALUES (?, ?, ?, ?)",
                (self.now, safe_event, safe_client_id, safe_detail),
            )

    def get_audit_events(self) -> list[AuditEvent]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
            return [
                AuditEvent(
                    id=row["id"],
                    ts=row["ts"],
                    event=row["event"],
                    client_id=row["client_id"],
                    detail=row["detail"],
                )
                for row in rows
            ]

    # -----------------------------------------------------------------------
    # Plaintext Security Scan Helper
    # -----------------------------------------------------------------------

    def scan_all_text_columns(self) -> list[str]:
        """Return all text values across all tables to verify no secrets are stored plaintext."""
        with self._lock:
            values: list[str] = []
            tables = [
                row[0]
                for row in self._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                if not row[0].startswith("sqlite_")
            ]
            for tbl in tables:
                col_info = self._conn.execute(f"PRAGMA table_info({tbl})").fetchall()
                text_cols = [col[1] for col in col_info if "TEXT" in col[2].upper()]
                for col in text_cols:
                    rows = self._conn.execute(f"SELECT {col} FROM {tbl} WHERE {col} IS NOT NULL").fetchall()
                    for r in rows:
                        values.append(str(r[0]))
            return values
