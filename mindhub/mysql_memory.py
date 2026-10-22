"""MySQL persistence for Memory records.

This adapter is intentionally independent of the production gateway wiring. It
expects the standalone memory.sql schema and a DB-API connection factory.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Callable, Mapping

from .memory import (
    Memory,
    MemoryPersistenceError,
    MemoryRecord,
)


ConnectionFactory = Callable[[], object]


class MySQLMemoryPersistence:
    """Transactional MySQL backend for Memory records."""

    TABLE = "memories"

    def __init__(self, connection_factory: ConnectionFactory) -> None:
        self._connection_factory = connection_factory

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        prefix: str = "MYSQL",
    ) -> "MySQLMemoryPersistence":
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

    def store(self, record: MemoryRecord) -> Memory:
        """Insert a new memory row and return the persisted Memory."""
        connection = self._connection_factory()
        cursor = None
        try:
            _begin(connection)
            cursor = connection.cursor()
            cursor.execute(
                f"INSERT INTO {self.TABLE} "
                "(project_id, memory_type, content, source, explicitness) "
                "VALUES (%s, %s, %s, %s, %s)",
                (
                    record.project_id,
                    record.memory_type,
                    record.content,
                    record.source,
                    record.explicitness,
                ),
            )
            inserted_id = cursor.lastrowid
            cursor.execute(
                f"SELECT id, project_id, memory_type, content, source, explicitness, created_at "
                f"FROM {self.TABLE} WHERE id = %s",
                (inserted_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("inserted memory row could not be fetched")
            connection.commit()
            return _memory_from_row(row)
        except MemoryPersistenceError:
            _rollback(connection)
            raise
        except Exception as exc:
            _rollback(connection)
            raise MemoryPersistenceError("memory persistence failed") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def search(self, query: str, *, limit: int = 10) -> tuple[Memory, ...]:
        """Search active non-expired memories by content substring."""
        connection = self._connection_factory()
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute(
                f"SELECT id, project_id, memory_type, content, source, explicitness, created_at "
                f"FROM {self.TABLE} "
                "WHERE status = 'active' "
                "  AND (expires_at IS NULL OR expires_at > NOW()) "
                "  AND content LIKE CONCAT('%', %s, '%') "
                "ORDER BY updated_at DESC "
                "LIMIT %s",
                (query, limit),
            )
            rows = cursor.fetchall()
            return tuple(_memory_from_row(row) for row in rows)
        except Exception as exc:
            raise MemoryPersistenceError("memory search failed") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def connect(self) -> object:
        """Create and return a new database connection from the configured factory."""
        return self._connection_factory()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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


def _as_utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _memory_from_row(row: tuple[object, ...]) -> Memory:
    # row: id, project_id, memory_type, content, source, explicitness, created_at
    return Memory(
        id=int(row[0]),
        project_id=int(row[1]) if row[1] is not None else None,
        memory_type=str(row[2]),
        content=str(row[3]),
        source=str(row[4]) if row[4] is not None else None,
        explicitness=str(row[5]),
        created_at=_as_utc_aware(row[6]),  # type: ignore[arg-type]
    )
