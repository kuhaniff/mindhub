"""MySQL persistence for immutable Project State snapshots.

This adapter is intentionally independent of the production gateway wiring. It
expects the standalone project_state.sql schema and a DB-API connection factory.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Callable, Mapping
from uuid import uuid4

from .project_state import (
    ProjectState,
    ProjectStatePersistence,
    ProjectStatePersistenceError,
    ProjectStateSnapshot,
)


ConnectionFactory = Callable[[], object]


class MySQLProjectStatePersistence(ProjectStatePersistence):
    """Transactional MySQL backend for Project State snapshots."""

    SNAPSHOTS_TABLE = "project_state_snapshots"
    CURRENT_TABLE = "project_state_current"

    def __init__(self, connection_factory: ConnectionFactory) -> None:
        self._connection_factory = connection_factory

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        prefix: str = "MYSQL",
    ) -> "MySQLProjectStatePersistence":
        """Create a backend from MYSQL_*-style settings without logging them."""
        values = environ if environ is not None else os.environ
        required = ("HOST", "PORT", "DATABASE", "USER", "PASSWORD")
        missing = [f"{prefix}_{key}" for key in required if not values.get(f"{prefix}_{key}")]
        if missing:
            raise ValueError("missing database configuration: " + ", ".join(missing))

        try:
            import mysql.connector
        except ModuleNotFoundError as exc:
            raise RuntimeError("mysql-connector-python is required for MySQL persistence") from exc

        settings = {
            "host": values[f"{prefix}_HOST"],
            "port": int(values[f"{prefix}_PORT"]),
            "database": values[f"{prefix}_DATABASE"],
            "user": values[f"{prefix}_USER"],
            "password": values[f"{prefix}_PASSWORD"],
        }

        def connect() -> object:
            return mysql.connector.connect(**settings)

        return cls(connect)

    def create_snapshot(self, state: ProjectState) -> ProjectStateSnapshot:
        snapshot_id = str(uuid4())
        sequence: int
        timestamp = _as_utc_naive(state.updated_at)
        connection = self._connection_factory()
        cursor = None
        try:
            _begin(connection)
            cursor = connection.cursor()
            cursor.execute(
                f"INSERT INTO {self.CURRENT_TABLE} "
                "(project_id, last_sequence, current_snapshot_id, updated_at) "
                "VALUES (%s, 0, NULL, %s) "
                f"ON DUPLICATE KEY UPDATE project_id = {self.CURRENT_TABLE}.project_id",
                (state.project_id, timestamp),
            )
            cursor.execute(
                f"SELECT last_sequence FROM {self.CURRENT_TABLE} "
                "WHERE project_id = %s FOR UPDATE",
                (state.project_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("project state sequence row was not created")
            sequence = int(row[0]) + 1
            cursor.execute(
                f"INSERT INTO {self.SNAPSHOTS_TABLE} "
                "(snapshot_id, project_id, sequence, current_goal, status, progress, "
                "decisions, blockers, next_action, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
            cursor.execute(
                f"UPDATE {self.CURRENT_TABLE} SET last_sequence = %s, "
                "current_snapshot_id = %s, updated_at = %s WHERE project_id = %s",
                (sequence, snapshot_id, timestamp, state.project_id),
            )
            connection.commit()
            return ProjectStateSnapshot(snapshot_id=snapshot_id, sequence=sequence, state=state)
        except Exception as exc:
            _rollback(connection)
            raise ProjectStatePersistenceError("project state persistence failed") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def current(self, project_id: int) -> ProjectStateSnapshot | None:
        connection = self._connection_factory()
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute(
                f"SELECT {self._snapshot_columns()} FROM {self.SNAPSHOTS_TABLE} s "
                f"JOIN {self.CURRENT_TABLE} c ON c.current_snapshot_id = s.snapshot_id "
                "WHERE c.project_id = %s",
                (project_id,),
            )
            row = cursor.fetchone()
            return None if row is None else _snapshot_from_row(row)
        except Exception as exc:
            raise ProjectStatePersistenceError("project state read failed") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def history(self, project_id: int) -> tuple[ProjectStateSnapshot, ...]:
        connection = self._connection_factory()
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute(
                f"SELECT {self._snapshot_columns()} FROM {self.SNAPSHOTS_TABLE} s "
                "WHERE s.project_id = %s ORDER BY s.sequence ASC",
                (project_id,),
            )
            return tuple(_snapshot_from_row(row) for row in cursor.fetchall())
        except Exception as exc:
            raise ProjectStatePersistenceError("project state history read failed") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def connect(self) -> object:
        """Create and return a new database connection from the configured factory."""
        return self._connection_factory()

    @staticmethod
    def _snapshot_columns() -> str:
        return (
            "s.snapshot_id, s.project_id, s.sequence, s.current_goal, s.status, "
            "s.progress, s.decisions, s.blockers, s.next_action, s.updated_at"
        )


def _begin(connection: object) -> None:
    start_transaction = getattr(connection, "start_transaction", None)
    if callable(start_transaction):
        start_transaction()
    else:
        connection.begin()  # type: ignore[attr-defined]


def _rollback(connection: object) -> None:
    try:
        connection.rollback()  # type: ignore[attr-defined]
    except Exception:
        pass


def _as_utc_naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _as_utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _snapshot_from_row(row: tuple[object, ...]) -> ProjectStateSnapshot:
    decisions = json.loads(row[6]) if isinstance(row[6], str) else row[6]
    blockers = json.loads(row[7]) if isinstance(row[7], str) else row[7]
    state = ProjectState(
        project_id=int(row[1]),
        current_goal=str(row[3]),
        status=str(row[4]),
        progress=str(row[5]),
        decisions=tuple(decisions),
        blockers=tuple(blockers),
        next_action=row[8],  # type: ignore[arg-type]
        updated_at=_as_utc_aware(row[9]),  # type: ignore[arg-type]
    )
    return ProjectStateSnapshot(snapshot_id=str(row[0]), sequence=int(row[2]), state=state)
