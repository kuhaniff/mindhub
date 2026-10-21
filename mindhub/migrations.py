"""Database migration helper for mindhub Project State schema."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

SQL_PATH = Path(__file__).resolve().parent.parent / "sql" / "project_state.sql"


def get_migration_sql(path: Path | str | None = None) -> str:
    """Read the SQL migration file from the specified path or default package location."""
    file_path = Path(path) if path is not None else SQL_PATH
    if not file_path.is_file():
        raise FileNotFoundError(f"migration SQL file not found at {file_path}")
    return file_path.read_text(encoding="utf-8")


def apply_migrations(connection: object, sql: str | None = None) -> list[str]:
    """Execute migration DDL statements in order on the provided database connection.

    Returns the list of executed SQL statements.
    """
    raw_sql = sql if sql is not None else get_migration_sql()
    statements = [stmt.strip() for stmt in raw_sql.split(";") if stmt.strip()]

    cursor = None
    try:
        cursor = connection.cursor()
        for statement in statements:
            cursor.execute(statement)
        connection.commit()
    except Exception:
        rollback = getattr(connection, "rollback", None)
        if callable(rollback):
            rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()

    return statements


def run_migration_from_env(environ: dict | None = None) -> list[str]:
    """Connect to MySQL using environment variables and apply migrations."""
    from .mysql_project_state import MySQLProjectStatePersistence

    backend = MySQLProjectStatePersistence.from_env(environ)
    conn = backend._connection_factory()
    try:
        return apply_migrations(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    executed = run_migration_from_env()
    print(f"Successfully applied {len(executed)} migration statement(s).")
