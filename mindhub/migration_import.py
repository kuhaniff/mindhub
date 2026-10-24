"""Import an offline ai-memory JSONL export into a new SQLite staging DB.

This module is deliberately file-only: it does not read application settings,
connect to MySQL, or contact a running service.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any


_REQUIRED_FIELDS = (
    "id",
    "project_id",
    "memory_type",
    "content",
    "source",
    "explicitness",
    "status",
    "expires_at",
    "created_at",
    "updated_at",
)

_SOURCE_METADATA_FIELDS = ("confidence", "verified_at", "superseded_by")
_SQLITE_INTEGER_MIN = -(2**63)
_SQLITE_INTEGER_MAX = 2**63 - 1

_CREATE_SCHEMA = """
CREATE TABLE memories (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    memory_type TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT,
    explicitness TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_memories_status_updated ON memories (status, updated_at);
CREATE INDEX idx_memories_project ON memories (project_id);
CREATE TABLE memory_source_metadata (
    memory_id INTEGER PRIMARY KEY,
    confidence REAL,
    verified_at TEXT,
    superseded_by INTEGER,
    FOREIGN KEY (memory_id) REFERENCES memories (id) ON DELETE CASCADE
);
"""

_INSERT_MEMORY = """
INSERT INTO memories (
    id, project_id, memory_type, content, source, explicitness,
    status, expires_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_INSERT_SOURCE_METADATA = """
INSERT INTO memory_source_metadata (memory_id, confidence, verified_at, superseded_by)
VALUES (?, ?, ?, ?)
"""


class MigrationImportError(ValueError):
    """The export or staging destination is unsafe or invalid."""


def _required_string(record: dict[str, Any], field: str, line_number: int) -> str:
    value = record[field]
    if not isinstance(value, str) or not value:
        raise MigrationImportError(f"line {line_number}: {field} must be a non-empty string")
    return value


def _integer_in_sqlite_range(
    value: Any,
    field: str,
    line_number: int,
    *,
    positive: bool = False,
    nullable: bool = False,
) -> int | None:
    if nullable and value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < (1 if positive else _SQLITE_INTEGER_MIN)
        or value > _SQLITE_INTEGER_MAX
    ):
        qualifier = "positive " if positive else ""
        null_suffix = " or null" if nullable else ""
        raise MigrationImportError(
            f"line {line_number}: {field} must be a {qualifier}integer{null_suffix} "
            f"within SQLite signed 64-bit range"
        )
    return value


def _validate_record(value: Any, line_number: int) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    if not isinstance(value, dict):
        raise MigrationImportError(f"line {line_number}: record must be a JSON object")
    missing = [field for field in _REQUIRED_FIELDS if field not in value]
    if missing:
        raise MigrationImportError(
            f"line {line_number}: missing required field(s): {', '.join(missing)}"
        )

    record_id = _integer_in_sqlite_range(value["id"], "id", line_number, positive=True)
    project_id = _integer_in_sqlite_range(
        value["project_id"], "project_id", line_number, nullable=True
    )

    memory_type = _required_string(value, "memory_type", line_number)
    if len(memory_type) > 50:
        raise MigrationImportError(f"line {line_number}: memory_type exceeds 50 characters")
    content = _required_string(value, "content", line_number)
    if len(content) > 60000:
        raise MigrationImportError(f"line {line_number}: content exceeds 60000 characters")
    source = value["source"]
    if source is not None and (not isinstance(source, str) or not source):
        raise MigrationImportError(f"line {line_number}: source must be a non-empty string or null")
    explicitness = _required_string(value, "explicitness", line_number)
    status = _required_string(value, "status", line_number)
    expires_at = value["expires_at"]
    if expires_at is not None and (not isinstance(expires_at, str) or not expires_at):
        raise MigrationImportError(f"line {line_number}: expires_at must be a non-empty string or null")
    created_at = _required_string(value, "created_at", line_number)
    updated_at = _required_string(value, "updated_at", line_number)
    confidence = value.get("confidence")
    if confidence is not None and (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
    ):
        raise MigrationImportError(f"line {line_number}: confidence must be a finite number or null")
    verified_at = value.get("verified_at")
    if verified_at is not None and (not isinstance(verified_at, str) or not verified_at):
        raise MigrationImportError(f"line {line_number}: verified_at must be a non-empty string or null")
    superseded_by = _integer_in_sqlite_range(
        value.get("superseded_by"), "superseded_by", line_number, positive=True, nullable=True
    )
    return (
        (
            record_id, project_id, memory_type, content, source, explicitness,
            status, expires_at, created_at, updated_at,
        ),
        (record_id, confidence, verified_at, superseded_by),
    )


def _reject_preexisting_sidecars(destination: Path) -> None:
    for path in (Path(f"{destination}-wal"), Path(f"{destination}-shm")):
        if path.exists() or path.is_symlink():
            raise MigrationImportError(f"destination sidecar already exists: {path}")


def _remove_database_files(database: Path) -> None:
    for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _publish_staged_database(staged: Path, destination: Path) -> None:
    """Publish without replacing a path that appeared during the import."""
    try:
        _reject_preexisting_sidecars(destination)
        # A hard link is atomic and fails with EEXIST instead of replacing the
        # destination, unlike os.replace(). Both paths are in the same folder.
        os.link(staged, destination)
    except FileExistsError as exc:
        raise MigrationImportError(f"destination already exists: {destination}") from exc
    except OSError as exc:
        raise MigrationImportError(f"cannot publish staging destination {destination}: {exc}") from exc
    finally:
        _remove_database_files(staged)


def import_jsonl(export_path: str | os.PathLike[str], staging_db_path: str | os.PathLike[str]) -> int:
    """Atomically import *export_path* into a newly-created SQLite database.

    The destination must not already exist. Any validation or database error
    rolls back the transaction and removes the newly-created staging files.
    Returns the number of imported memories.
    """
    source = Path(export_path)
    destination = Path(staging_db_path)
    if not source.is_file():
        raise MigrationImportError(f"JSONL export does not exist: {source}")
    if not destination.parent.is_dir():
        raise MigrationImportError(f"destination directory does not exist: {destination.parent}")
    if destination.exists() or destination.is_symlink():
        raise MigrationImportError(f"destination already exists: {destination}")

    _reject_preexisting_sidecars(destination)
    try:
        descriptor, staged_name = tempfile.mkstemp(
            prefix=f".{destination.name}.import-",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(descriptor)
    except OSError as exc:
        raise MigrationImportError(f"cannot create temporary staging database: {exc}") from exc

    staged = Path(staged_name)
    connection: sqlite3.Connection | None = None
    seen_ids: set[int] = set()
    imported = 0
    try:
        connection = sqlite3.connect(staged)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(_CREATE_SCHEMA)
        connection.execute("BEGIN")
        with source.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    raise MigrationImportError(f"line {line_number}: blank lines are not allowed")
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise MigrationImportError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
                row, metadata_row = _validate_record(value, line_number)
                record_id = row[0]
                if record_id in seen_ids:
                    raise MigrationImportError(f"line {line_number}: duplicate id {record_id}")
                seen_ids.add(record_id)
                connection.execute(_INSERT_MEMORY, row)
                connection.execute(_INSERT_SOURCE_METADATA, metadata_row)
                imported += 1
        connection.commit()
    except (MigrationImportError, OSError, sqlite3.Error, UnicodeDecodeError) as exc:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
            try:
                connection.close()
            except Exception:
                pass
            connection = None
        _remove_database_files(staged)
        if isinstance(exc, UnicodeDecodeError):
            raise MigrationImportError(f"invalid UTF-8 in JSONL export {source}: {exc}") from exc
        raise
    except BaseException:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
            connection = None
        _remove_database_files(staged)
        raise
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    _publish_staged_database(staged, destination)
    return imported


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="offline JSONL export")
    parser.add_argument("staging_db", type=Path, help="new SQLite staging database path")
    args = parser.parse_args()
    try:
        count = import_jsonl(args.export, args.staging_db)
    except MigrationImportError as exc:
        parser.error(str(exc))
    print(f"Imported {count} memories into {args.staging_db}")


if __name__ == "__main__":
    main()
