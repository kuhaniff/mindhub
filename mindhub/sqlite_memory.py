"""SQLite persistence for Memory records.

Uses Python's built-in sqlite3 module. The database file path is read from
the MINDHUB_DB_PATH environment variable (default: ``mindhub.db``).
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from threading import RLock
from typing import Mapping

from .memory import Memory, MemoryPersistenceError, MemoryRecord


class SQLiteMemoryPersistence:
    """Thread-safe SQLite backend for Memory records.

    Creates the memories table automatically on first use.
    """

    TABLE = "memories"

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self._db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._ensure_schema()

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        default_path: str = "mindhub.db",
    ) -> "SQLiteMemoryPersistence":
        """Create a backend from the MINDHUB_DB_PATH environment variable."""
        values = environ if environ is not None else os.environ
        db_path = values.get("MINDHUB_DB_PATH", default_path)
        return cls(db_path)

    def _connect(self) -> sqlite3.Connection:
        """Return the managed database connection."""
        return self._conn

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER,
                    memory_type TEXT NOT NULL DEFAULT 'fact',
                    content TEXT NOT NULL,
                    source TEXT,
                    explicitness TEXT NOT NULL DEFAULT 'explicit',
                    status TEXT NOT NULL DEFAULT 'active',
                    expires_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_memories_status_updated
                    ON memories (status, updated_at);
                CREATE INDEX IF NOT EXISTS idx_memories_project
                    ON memories (project_id);
            """)
            self._conn.commit()

    def store(self, record: MemoryRecord) -> Memory:
        """Insert a new memory row and return the persisted Memory."""
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "INSERT INTO memories "
                    "(project_id, memory_type, content, source, explicitness, status) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        record.project_id,
                        record.memory_type,
                        record.content,
                        record.source,
                        record.explicitness,
                        record.status,
                    ),
                )
                inserted_id = cursor.lastrowid
                row = self._conn.execute(
                    "SELECT id, project_id, memory_type, content, source, "
                    "explicitness, created_at FROM memories WHERE id = ?",
                    (inserted_id,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("inserted memory row could not be fetched")
                self._conn.commit()
                return _memory_from_row(row)
            except MemoryPersistenceError:
                self._conn.rollback()
                raise
            except Exception as exc:
                self._conn.rollback()
                raise MemoryPersistenceError("memory persistence failed") from exc

    def search(self, query: str, *, limit: int = 10) -> tuple[Memory, ...]:
        """Search active non-expired memories by content substring."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        safe_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT id, project_id, memory_type, content, source, "
                    "explicitness, created_at FROM memories "
                    "WHERE status = 'active' "
                    "  AND (expires_at IS NULL OR expires_at > ?) "
                    "  AND content LIKE ? ESCAPE '\\' "
                    "ORDER BY updated_at DESC "
                    "LIMIT ?",
                    (now_iso, f"%{safe_query}%", limit),
                ).fetchall()
                return tuple(_memory_from_row(row) for row in rows)
            except Exception as exc:
                raise MemoryPersistenceError("memory search failed") from exc

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()


def _memory_from_row(row: sqlite3.Row) -> Memory:
    created_at_raw = row["created_at"]
    created_at: datetime
    if isinstance(created_at_raw, datetime):
        created_at = created_at_raw if created_at_raw.tzinfo else created_at_raw.replace(tzinfo=timezone.utc)
    else:
        try:
            created_at = datetime.fromisoformat(str(created_at_raw)).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            created_at = datetime.now(timezone.utc)
    return Memory(
        id=int(row["id"]),
        project_id=int(row["project_id"]) if row["project_id"] is not None else None,
        memory_type=str(row["memory_type"]),
        content=str(row["content"]),
        source=str(row["source"]) if row["source"] is not None else None,
        explicitness=str(row["explicitness"]),
        created_at=created_at,
    )
