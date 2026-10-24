"""Tests for the offline ai-memory JSONL staging importer."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mindhub.migration_import import MigrationImportError, import_jsonl


FIELDS = {
    "id": 7,
    "project_id": 3,
    "memory_type": "fact",
    "content": "staged memory",
    "source": "ai-memory",
    "explicitness": "explicit",
    "status": "active",
    "expires_at": None,
    "created_at": "2026-10-24T03:00:00.123456+00:00",
    "updated_at": "2026-10-24T03:00:01.123456+00:00",
}


class TestMigrationImport(unittest.TestCase):
    def test_import_preserves_export_fields_in_new_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            second = dict(FIELDS, id=8, project_id=None, expires_at="2027-01-01T00:00:00Z")
            export.write_text("\n".join(json.dumps(row) for row in (FIELDS, second)) + "\n", encoding="utf-8")

            result = import_jsonl(export, database)

            self.assertEqual(result, 2)
            with sqlite3.connect(database) as connection:
                rows = connection.execute(
                    "SELECT id, project_id, memory_type, content, source, explicitness, "
                    "status, expires_at, created_at, updated_at FROM memories ORDER BY id"
                ).fetchall()
            self.assertEqual(rows, [
                tuple(FIELDS.values()),
                tuple(second.values()),
            ])

    def test_import_preserves_source_only_metadata_separately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            record = dict(
                FIELDS,
                confidence=0.875,
                verified_at="2026-10-24T03:05:00",
                superseded_by=12,
            )
            export.write_text(json.dumps(record) + "\n", encoding="utf-8")

            import_jsonl(export, database)

            with sqlite3.connect(database) as connection:
                metadata = connection.execute(
                    "SELECT memory_id, confidence, verified_at, superseded_by "
                    "FROM memory_source_metadata"
                ).fetchall()
                memory_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(memories)")
                }
            self.assertEqual(metadata, [(7, 0.875, "2026-10-24T03:05:00", 12)])
            self.assertEqual(
                memory_columns,
                {
                    "id", "project_id", "memory_type", "content", "source",
                    "explicitness", "status", "expires_at", "created_at", "updated_at",
                },
            )

    def test_import_without_source_only_metadata_uses_null_staging_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(json.dumps(FIELDS) + "\n", encoding="utf-8")

            import_jsonl(export, database)

            with sqlite3.connect(database) as connection:
                metadata = connection.execute(
                    "SELECT memory_id, confidence, verified_at, superseded_by "
                    "FROM memory_source_metadata"
                ).fetchall()
            self.assertEqual(metadata, [(7, None, None, None)])

    def test_duplicate_ids_fail_and_leave_no_partial_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(
                json.dumps(FIELDS) + "\n" + json.dumps(FIELDS) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(MigrationImportError, "duplicate id"):
                import_jsonl(export, database)

            self.assertFalse(database.exists())

    def test_invalid_record_rolls_back_and_reports_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            invalid = dict(FIELDS)
            invalid.pop("updated_at")
            export.write_text(
                json.dumps(FIELDS) + "\n" + json.dumps(invalid) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(MigrationImportError, r"line 2.*updated_at"):
                import_jsonl(export, database)

            self.assertFalse(database.exists())

    def test_existing_destination_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(json.dumps(FIELDS) + "\n", encoding="utf-8")
            database.write_bytes(b"sentinel")

            with self.assertRaisesRegex(MigrationImportError, "already exists"):
                import_jsonl(export, database)

            self.assertEqual(database.read_bytes(), b"sentinel")

    def test_destination_created_during_import_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(json.dumps(FIELDS) + "\n", encoding="utf-8")

            real_link = __import__("os").link

            def create_destination_before_publish(staged: Path, destination: Path) -> None:
                database.write_bytes(b"raced sentinel")
                real_link(staged, destination)

            with patch("mindhub.migration_import.os.link", side_effect=create_destination_before_publish):
                with self.assertRaisesRegex(MigrationImportError, "destination already exists"):
                    import_jsonl(export, database)

            self.assertEqual(database.read_bytes(), b"raced sentinel")
            self.assertEqual(list(root.glob(".staging.db.import-*.tmp*")), [])

    def test_out_of_range_integer_rolls_back_and_removes_staging_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for field in ("id", "project_id", "superseded_by"):
                with self.subTest(field=field):
                    export = root / f"{field}.jsonl"
                    database = root / f"{field}.db"
                    record = dict(FIELDS)
                    record[field] = 2**63
                    if field == "project_id":
                        record["id"] = 8
                    export.write_text(json.dumps(record) + "\n", encoding="utf-8")

                    with self.assertRaisesRegex(MigrationImportError, field):
                        import_jsonl(export, database)

                    self.assertFalse(database.exists())

    def test_blank_lines_are_rejected_and_remove_staging_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(json.dumps(FIELDS) + "\n\n", encoding="utf-8")

            with self.assertRaisesRegex(MigrationImportError, r"line 2.*blank lines are not allowed"):
                import_jsonl(export, database)

            self.assertFalse(database.exists())

    def test_malformed_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text("not json\n", encoding="utf-8")

            with self.assertRaisesRegex(MigrationImportError, r"line 1.*JSON"):
                import_jsonl(export, database)
            self.assertFalse(database.exists())

    def test_preexisting_sidecars_remain_untouched_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_bytes(json.dumps(FIELDS).encode("utf-8") + b"\n\xff")

            with self.assertRaisesRegex(MigrationImportError, r"invalid UTF-8.*memories.jsonl"):
                import_jsonl(export, database)

            self.assertFalse(database.exists())

    def test_preexisting_sidecars_are_rejected_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "memories.jsonl"
            database = root / "staging.db"
            export.write_text(json.dumps(FIELDS) + "\n", encoding="utf-8")
            wal = root / "staging.db-wal"
            shm = root / "staging.db-shm"
            wal.write_bytes(b"wal")
            shm.write_bytes(b"shm")

            with self.assertRaisesRegex(MigrationImportError, "sidecar already exists"):
                import_jsonl(export, database)

            self.assertFalse(database.exists())
            self.assertEqual(wal.read_bytes(), b"wal")
            self.assertEqual(shm.read_bytes(), b"shm")


if __name__ == "__main__":
    unittest.main()
