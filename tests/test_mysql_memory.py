"""Unit tests for mysql_memory.py using MagicMock (no real DB)."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

from mindhub.memory import Memory, MemoryPersistenceError, MemoryRecord


def _make_row(
    id: int = 1,
    project_id=None,
    memory_type: str = "fact",
    content: str = "test content",
    source=None,
    explicitness: str = "explicit",
    created_at: datetime | None = None,
) -> tuple:
    if created_at is None:
        created_at = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return (id, project_id, memory_type, content, source, explicitness, created_at)


def _make_persistence(mock_connection: MagicMock):
    """Build a MySQLMemoryPersistence wired to a pre-configured mock connection."""
    from mindhub.mysql_memory import MySQLMemoryPersistence

    factory = MagicMock(return_value=mock_connection)
    return MySQLMemoryPersistence(connection_factory=factory)


class TestMySQLMemoryStore(unittest.TestCase):
    def test_store_executes_insert(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.lastrowid = 7
        cursor.fetchone.return_value = _make_row(id=7, content="my note")

        persistence = _make_persistence(conn)
        record = MemoryRecord(content="my note", memory_type="fact")
        persistence.store(record)

        insert_call = cursor.execute.call_args_list[0]
        sql = insert_call[0][0]
        self.assertIn("INSERT INTO", sql)
        params = insert_call[0][1]
        self.assertIn("my note", params)

    def test_store_returns_memory_with_id(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.lastrowid = 42
        cursor.fetchone.return_value = _make_row(id=42, content="stored memory")

        persistence = _make_persistence(conn)
        record = MemoryRecord(content="stored memory")
        result = persistence.store(record)

        self.assertIsInstance(result, Memory)
        self.assertEqual(result.id, 42)
        self.assertEqual(result.content, "stored memory")

    def test_store_rolls_back_on_failure(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.execute.side_effect = Exception("db error")

        persistence = _make_persistence(conn)
        record = MemoryRecord(content="will fail")

        with self.assertRaises(MemoryPersistenceError):
            persistence.store(record)

        conn.rollback.assert_called()

    def test_store_commits_on_success(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.lastrowid = 1
        cursor.fetchone.return_value = _make_row(id=1, content="committed")

        persistence = _make_persistence(conn)
        persistence.store(MemoryRecord(content="committed"))

        conn.commit.assert_called_once()


class TestMySQLMemorySearch(unittest.TestCase):
    def test_search_executes_select(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.fetchall.return_value = [_make_row(id=1, content="homelab notes")]

        persistence = _make_persistence(conn)
        results = persistence.search("homelab")

        select_call = cursor.execute.call_args_list[0]
        sql = select_call[0][0]
        self.assertIn("SELECT", sql)
        self.assertIn("status = 'active'", sql)
        self.assertIsInstance(results, tuple)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].content, "homelab notes")

    def test_search_respects_limit(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.fetchall.return_value = []

        persistence = _make_persistence(conn)
        persistence.search("query", limit=7)

        execute_call = cursor.execute.call_args_list[0]
        params = execute_call[0][1]
        self.assertIn(7, params)

    def test_search_raises_persistence_error_on_db_failure(self) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.execute.side_effect = Exception("connection lost")

        persistence = _make_persistence(conn)

        with self.assertRaises(MemoryPersistenceError):
            persistence.search("query")


class TestMySQLMemoryFromEnv(unittest.TestCase):
    def test_from_env_raises_on_missing_vars(self) -> None:
        from mindhub.mysql_memory import MySQLMemoryPersistence

        with self.assertRaises(ValueError):
            MySQLMemoryPersistence.from_env({})

    def test_from_env_raises_on_partial_vars(self) -> None:
        from mindhub.mysql_memory import MySQLMemoryPersistence

        partial_env = {
            "MYSQL_HOST": "localhost",
            "MYSQL_PORT": "3306",
            # missing DATABASE, USER, PASSWORD
        }
        with self.assertRaises(ValueError):
            MySQLMemoryPersistence.from_env(partial_env)


if __name__ == "__main__":
    unittest.main()
