"""SQLite persistence for immutable Project State snapshots."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from threading import RLock
from typing import Mapping
from uuid import uuid4

from .project_state import (
    ProjectState,
    ProjectStatePersistence,
    ProjectStatePersistenceError,
    ProjectStateSnapshot,
)


class SQLiteProjectStatePersistence(ProjectStatePersistence):
    """Thread-safe SQLite backend for Project State snapshots."""

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
    ) -> "SQLiteProjectStatePersistence":
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
                CREATE TABLE IF NOT EXISTS project_state_snapshots (
                    snapshot_id TEXT NOT NULL,
                    project_id INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    current_goal TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress TEXT NOT NULL,
                    decisions TEXT NOT NULL DEFAULT '[]',
                    blockers TEXT NOT NULL DEFAULT '[]',
                    next_action TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id)
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_project_seq
                    ON project_state_snapshots (project_id, sequence);

                CREATE TABLE IF NOT EXISTS project_state_current (
                    project_id INTEGER NOT NULL PRIMARY KEY,
                    last_sequence INTEGER NOT NULL DEFAULT 0,
                    current_snapshot_id TEXT,
                    updated_at TEXT NOT NULL
                );
            """)
            self._conn.commit()

    def create_snapshot(self, state: ProjectState) -> ProjectStateSnapshot:
        snapshot_id = str(uuid4())
        timestamp = state.updated_at.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            try:
                # Upsert into current table (insert if not exists)
                self._conn.execute(
                    "INSERT OR IGNORE INTO project_state_current "
                    "(project_id, last_sequence, current_snapshot_id, updated_at) "
                    "VALUES (?, 0, NULL, ?)",
                    (state.project_id, timestamp),
                )
                row = self._conn.execute(
                    "SELECT last_sequence FROM project_state_current "
                    "WHERE project_id = ?",
                    (state.project_id,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("project state sequence row was not created")
                sequence = int(row["last_sequence"]) + 1
                self._conn.execute(
                    "INSERT INTO project_state_snapshots "
                    "(snapshot_id, project_id, sequence, current_goal, status, progress, "
                    "decisions, blockers, next_action, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        snapshot_id,
                        state.project_id,
                        sequence,
                        state.current_goal,
                        state.status,
                        state.progress,
                        json.dumps(list(state.decisions), ensure_ascii=False),
                        json.dumps(list(state.blockers), ensure_ascii=False),
                        state.next_action,
                        timestamp,
                    ),
                )
                self._conn.execute(
                    "UPDATE project_state_current SET last_sequence = ?, "
                    "current_snapshot_id = ?, updated_at = ? WHERE project_id = ?",
                    (sequence, snapshot_id, timestamp, state.project_id),
                )
                self._conn.commit()
                return ProjectStateSnapshot(snapshot_id=snapshot_id, sequence=sequence, state=state)
            except Exception as exc:
                self._conn.rollback()
                raise ProjectStatePersistenceError("project state persistence failed") from exc

    def current(self, project_id: int) -> ProjectStateSnapshot | None:
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT s.snapshot_id, s.project_id, s.sequence, s.current_goal, "
                    "s.status, s.progress, s.decisions, s.blockers, s.next_action, s.updated_at "
                    "FROM project_state_snapshots s "
                    "JOIN project_state_current c ON c.current_snapshot_id = s.snapshot_id "
                    "WHERE c.project_id = ?",
                    (project_id,),
                ).fetchone()
                return None if row is None else _snapshot_from_row(row)
            except Exception as exc:
                raise ProjectStatePersistenceError("project state read failed") from exc

    def history(self, project_id: int) -> tuple[ProjectStateSnapshot, ...]:
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT s.snapshot_id, s.project_id, s.sequence, s.current_goal, "
                    "s.status, s.progress, s.decisions, s.blockers, s.next_action, s.updated_at "
                    "FROM project_state_snapshots s "
                    "WHERE s.project_id = ? ORDER BY s.sequence ASC",
                    (project_id,),
                ).fetchall()
                return tuple(_snapshot_from_row(row) for row in rows)
            except Exception as exc:
                raise ProjectStatePersistenceError("project state history read failed") from exc

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()


def _snapshot_from_row(row: sqlite3.Row) -> ProjectStateSnapshot:
    decisions = json.loads(row["decisions"]) if isinstance(row["decisions"], str) else row["decisions"]
    blockers = json.loads(row["blockers"]) if isinstance(row["blockers"], str) else row["blockers"]
    updated_at_raw = row["updated_at"]
    if isinstance(updated_at_raw, datetime):
        updated_at = updated_at_raw if updated_at_raw.tzinfo else updated_at_raw.replace(tzinfo=timezone.utc)
    else:
        try:
            updated_at = datetime.fromisoformat(str(updated_at_raw)).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            updated_at = datetime.now(timezone.utc)
    state = ProjectState(
        project_id=int(row["project_id"]),
        current_goal=str(row["current_goal"]),
        status=str(row["status"]),
        progress=str(row["progress"]),
        decisions=tuple(decisions),
        blockers=tuple(blockers),
        next_action=row["next_action"],
        updated_at=updated_at,
    )
    return ProjectStateSnapshot(
        snapshot_id=str(row["snapshot_id"]),
        sequence=int(row["sequence"]),
        state=state,
    )
