"""Unit tests for sqlite_memory.py using a real in-memory SQLite database."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from mindhub.memory import Memory, MemoryPersistenceError, MemoryRecord
from mindhub.sqlite_memory import SQLiteMemoryPersistence


def _make_persistence() -> SQLiteMemoryPersistence:
    """Create a fresh in-memory SQLite persistence for each test."""
    return SQLiteMemoryPersistence(":memory:")


class TestSQLiteMemoryStore(unittest.TestCase):
    def test_store_returns_memory_with_id(self) -> None:
        p = _make_persistence()
        record = MemoryRecord(content="homelab notes", memory_type="fact")
        result = p.store(record)
        self.assertIsInstance(result, Memory)
        self.assertGreater(result.id, 0)
        self.assertEqual(result.content, "homelab notes")

    def test_store_increments_id(self) -> None:
        p = _make_persistence()
        r1 = p.store(MemoryRecord(content="first"))
        r2 = p.store(MemoryRecord(content="second"))
        self.assertGreater(r2.id, r1.id)

    def test_store_sets_defaults(self) -> None:
        p = _make_persistence()
        result = p.store(MemoryRecord(content="test"))
        self.assertEqual(result.memory_type, "fact")
        self.assertEqual(result.explicitness, "explicit")
        self.assertIsNone(result.source)
        self.assertIsNone(result.project_id)

    def test_store_preserves_all_fields(self) -> None:
        p = _make_persistence()
        result = p.store(MemoryRecord(
            content="detailed note",
            memory_type="observation",
            source="hermes",
            project_id=5,
        ))
        self.assertEqual(result.content, "detailed note")
        self.assertEqual(result.memory_type, "observation")
        self.assertEqual(result.source, "hermes")
        self.assertEqual(result.project_id, 5)

    def test_store_created_at_is_datetime(self) -> None:
        p = _make_persistence()
        result = p.store(MemoryRecord(content="datetime check"))
        self.assertIsInstance(result.created_at, datetime)


class TestSQLiteMemorySearch(unittest.TestCase):
    def test_search_finds_matching_content(self) -> None:
        p = _make_persistence()
        p.store(MemoryRecord(content="homelab setup notes"))
        results = p.search("homelab")
        self.assertEqual(len(results), 1)
        self.assertIn("homelab", results[0].content)

    def test_search_case_insensitive(self) -> None:
        p = _make_persistence()
        p.store(MemoryRecord(content="Homelab Server Config"))
        results = p.search("homelab")
        self.assertEqual(len(results), 1)

    def test_search_returns_empty_for_no_match(self) -> None:
        p = _make_persistence()
        p.store(MemoryRecord(content="totally unrelated"))
        results = p.search("zzz_not_found")
        self.assertEqual(len(results), 0)

    def test_search_respects_limit(self) -> None:
        p = _make_persistence()
        for i in range(5):
            p.store(MemoryRecord(content=f"memory {i}"))
        results = p.search("memory", limit=2)
        self.assertEqual(len(results), 2)

    def test_search_returns_only_active(self) -> None:
        p = _make_persistence()
        conn = p._connect()
        conn.execute(
            "INSERT INTO memories (content, memory_type, explicitness, status) "
            "VALUES (?, 'fact', 'explicit', 'archived')",
            ("archived memory",),
        )
        conn.commit()
        results = p.search("archived")
        self.assertEqual(len(results), 0)

    def test_search_excludes_expired(self) -> None:
        p = _make_persistence()
        conn = p._connect()
        conn.execute(
            "INSERT INTO memories (content, memory_type, explicitness, status, expires_at) "
            "VALUES (?, 'fact', 'explicit', 'active', '2000-01-01T00:00:00')",
            ("expired memory",),
        )
        conn.commit()
        results = p.search("expired")
        self.assertEqual(len(results), 0)

    def test_search_limit_default_is_ten(self) -> None:
        p = _make_persistence()
        for i in range(15):
            p.store(MemoryRecord(content=f"bulk memory {i}"))
        results = p.search("bulk")
        self.assertLessEqual(len(results), 10)

    def test_search_returns_tuple(self) -> None:
        p = _make_persistence()
        results = p.search("anything")
        self.assertIsInstance(results, tuple)

    def test_search_escapes_like_wildcards(self) -> None:
        p = _make_persistence()
        p.store(MemoryRecord(content="100% discount deal"))
        p.store(MemoryRecord(content="1000 items in stock"))
        p.store(MemoryRecord(content="variable_name in code"))
        p.store(MemoryRecord(content="variableXname in code"))

        percent_results = p.search("100%")
        self.assertEqual(len(percent_results), 1)
        self.assertEqual(percent_results[0].content, "100% discount deal")

        underscore_results = p.search("variable_name")
        self.assertEqual(len(underscore_results), 1)
        self.assertEqual(underscore_results[0].content, "variable_name in code")


class TestSQLiteMemoryFromEnv(unittest.TestCase):
    def test_from_env_uses_default_path(self) -> None:
        p = SQLiteMemoryPersistence.from_env({}, default_path=":memory:")
        self.assertIsInstance(p, SQLiteMemoryPersistence)

    def test_from_env_reads_env_var(self) -> None:
        p = SQLiteMemoryPersistence.from_env({"MINDHUB_DB_PATH": ":memory:"})
        self.assertIsInstance(p, SQLiteMemoryPersistence)


if __name__ == "__main__":
    unittest.main()
