"""Unit tests for memory.py using InMemoryMemoryPersistence."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from mindhub.memory import (
    InMemoryMemoryPersistence,
    MemoryRecord,
    remember_memory,
    search_memories,
)


class TestRememberMemory(unittest.TestCase):
    def setUp(self) -> None:
        self.persistence = InMemoryMemoryPersistence()

    def test_remember_returns_dict_with_id(self) -> None:
        result = remember_memory(self.persistence, "homelab notes")
        self.assertIn("id", result)
        self.assertGreater(result["id"], 0)

    def test_remember_with_all_fields(self) -> None:
        result = remember_memory(
            self.persistence,
            "detailed note",
            memory_type="observation",
            source="manual",
            project_id=42,
        )
        self.assertEqual(result["memory_type"], "observation")
        self.assertEqual(result["source"], "manual")
        self.assertEqual(result["project_id"], 42)
        self.assertIn("id", result)
        self.assertIn("created_at", result)

    def test_remember_validates_empty_content(self) -> None:
        with self.assertRaises(ValueError):
            remember_memory(self.persistence, "")

    def test_remember_validates_content_too_long(self) -> None:
        with self.assertRaises(ValueError):
            remember_memory(self.persistence, "x" * 60001)

    def test_remember_validates_memory_type_too_long(self) -> None:
        with self.assertRaises(ValueError):
            remember_memory(self.persistence, "content", memory_type="t" * 51)


class TestSearchMemories(unittest.TestCase):
    def setUp(self) -> None:
        self.persistence = InMemoryMemoryPersistence()

    def test_search_finds_matching_content(self) -> None:
        remember_memory(self.persistence, "homelab notes")
        results = search_memories(self.persistence, "homelab")
        self.assertEqual(len(results), 1)
        self.assertIn("homelab notes", results[0]["content"])

    def test_search_case_insensitive(self) -> None:
        remember_memory(self.persistence, "Homelab setup details")
        results = search_memories(self.persistence, "homelab")
        self.assertEqual(len(results), 1)

    def test_search_returns_empty_for_no_match(self) -> None:
        remember_memory(self.persistence, "something unrelated")
        results = search_memories(self.persistence, "zzz")
        self.assertEqual(results, [])

    def test_search_respects_limit(self) -> None:
        for i in range(5):
            remember_memory(self.persistence, f"matching note {i}")
        results = search_memories(self.persistence, "matching", limit=2)
        self.assertEqual(len(results), 2)

    def test_search_validates_empty_query(self) -> None:
        with self.assertRaises(ValueError):
            search_memories(self.persistence, "")

    def test_search_validates_limit_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            search_memories(self.persistence, "query", limit=0)
        with self.assertRaises(ValueError):
            search_memories(self.persistence, "query", limit=51)

    def test_search_limit_boundary(self) -> None:
        # limit=1 and limit=50 should both be valid (no exception)
        remember_memory(self.persistence, "boundary test note")
        results_min = search_memories(self.persistence, "boundary", limit=1)
        self.assertEqual(len(results_min), 1)
        results_max = search_memories(self.persistence, "boundary", limit=50)
        self.assertEqual(len(results_max), 1)


class TestInMemoryFiltering(unittest.TestCase):
    """Direct InMemoryMemoryPersistence tests for status and expiry filtering."""

    def setUp(self) -> None:
        self.persistence = InMemoryMemoryPersistence()

    def test_inactive_memory_not_returned(self) -> None:
        record = MemoryRecord(content="archived note", status="archived")
        self.persistence.store(record)
        results = self.persistence.search("archived")
        self.assertEqual(len(results), 0)

    def test_expired_memory_not_returned(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        record = MemoryRecord(content="expired note", expires_at=past)
        self.persistence.store(record)
        results = self.persistence.search("expired")
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
