"""Memory model, persistence contract, in-memory backend, and handler functions.

This module is local-only. It does not assume a production database schema,
migration, endpoint or gateway runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Protocol


class MemoryPersistenceError(RuntimeError):
    """Persistence operation failed before the record was committed."""


@dataclass(frozen=True)
class Memory:
    """Immutable result returned from persistence (has id and all server fields)."""

    id: int
    project_id: int | None
    memory_type: str
    content: str
    source: str | None
    explicitness: str
    created_at: datetime

    def as_dict(self) -> dict:
        """Return a plain dict suitable for serialisation."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "source": self.source,
            "explicitness": self.explicitness,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class MemoryRecord:
    """Input for storing a new memory (no id, no created_at/updated_at)."""

    content: str
    memory_type: str = "fact"
    source: str | None = None
    project_id: int | None = None
    explicitness: str = "explicit"
    status: str = "active"
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, str) or not self.content:
            raise ValueError("content must be a non-empty string")
        if len(self.content) > 60000:
            raise ValueError("content must not exceed 60000 characters")
        if not isinstance(self.memory_type, str) or not self.memory_type:
            raise ValueError("memory_type must be a non-empty string")
        if len(self.memory_type) > 50:
            raise ValueError("memory_type must not exceed 50 characters")
        if self.source is not None:
            if not isinstance(self.source, str) or not self.source:
                raise ValueError("source must be a non-empty string or None")


class MemoryPersistence(Protocol):
    """Persistence contract required by the memory handlers."""

    def search(self, query: str, *, limit: int = 10) -> tuple[Memory, ...]:
        ...

    def store(self, record: MemoryRecord) -> Memory:
        ...


class InMemoryMemoryPersistence:
    """Thread-safe in-memory backend for testing."""

    def __init__(self) -> None:
        self._store: list[tuple[int, str, str, MemoryRecord, datetime]] = []
        # (id, status, expires_at_str, record, created_at)
        self._records: list[dict] = []
        self._counter: int = 0
        self._lock = RLock()

    def store(self, record: MemoryRecord) -> Memory:
        with self._lock:
            self._counter += 1
            now = datetime.now(timezone.utc)
            entry = {
                "id": self._counter,
                "record": record,
                "created_at": now,
                "status": record.status,
                "expires_at": record.expires_at,
            }
            self._records.append(entry)
            return Memory(
                id=self._counter,
                project_id=record.project_id,
                memory_type=record.memory_type,
                content=record.content,
                source=record.source,
                explicitness=record.explicitness,
                created_at=now,
            )

    def search(self, query: str, *, limit: int = 10) -> tuple[Memory, ...]:
        now = datetime.now(timezone.utc)
        results: list[Memory] = []
        with self._lock:
            for entry in self._records:
                if entry["status"] != "active":
                    continue
                expires_at = entry["expires_at"]
                if expires_at is not None:
                    # Make expires_at timezone-aware for comparison if needed
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    if expires_at <= now:
                        continue
                record: MemoryRecord = entry["record"]
                if query.lower() in record.content.lower():
                    results.append(
                        Memory(
                            id=entry["id"],
                            project_id=record.project_id,
                            memory_type=record.memory_type,
                            content=record.content,
                            source=record.source,
                            explicitness=record.explicitness,
                            created_at=entry["created_at"],
                        )
                    )
                    if len(results) >= limit:
                        break
        return tuple(results)


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------


def search_memories(
    persistence: MemoryPersistence,
    query: str,
    *,
    limit: int = 10,
) -> list[dict]:
    """Validate inputs and search memories, returning a list of dicts."""
    if not isinstance(query, str) or not query:
        raise ValueError("query must be a non-empty string")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50 (inclusive)")
    memories = persistence.search(query, limit=limit)
    return [m.as_dict() for m in memories]


def remember_memory(
    persistence: MemoryPersistence,
    content: str,
    *,
    memory_type: str = "fact",
    source: str | None = None,
    project_id: int | None = None,
) -> dict:
    """Validate inputs, build a MemoryRecord, persist it and return a dict."""
    if not isinstance(content, str) or not content:
        raise ValueError("content must be a non-empty string")
    if len(content) > 60000:
        raise ValueError("content must not exceed 60000 characters")
    if not isinstance(memory_type, str) or not memory_type:
        raise ValueError("memory_type must be a non-empty string")
    if len(memory_type) > 50:
        raise ValueError("memory_type must not exceed 50 characters")
    if source is not None and (not isinstance(source, str) or not source):
        raise ValueError("source must be a non-empty string or None")

    record = MemoryRecord(
        content=content,
        memory_type=memory_type,
        source=source,
        project_id=project_id,
    )
    memory = persistence.store(record)
    return memory.as_dict()
