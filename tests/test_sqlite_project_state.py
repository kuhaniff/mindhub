"""Unit tests for sqlite_project_state.py using a real in-memory SQLite database."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from mindhub.project_state import (
    ProjectState,
    ProjectStateSnapshot,
    ProjectStatePersistenceError,
)
from mindhub.sqlite_project_state import SQLiteProjectStatePersistence


def _make_persistence() -> SQLiteProjectStatePersistence:
    return SQLiteProjectStatePersistence(":memory:")


def _make_state(
    project_id: int = 1,
    status: str = "in_progress",
    goal: str = "Build Mindhub",
    progress: str = "50%",
) -> ProjectState:
    return ProjectState(
        project_id=project_id,
        current_goal=goal,
        status=status,
        progress=progress,
        decisions=("use sqlite",),
        blockers=(),
        next_action="run tests",
        updated_at=datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


class TestSQLiteProjectStateCreate(unittest.TestCase):
    def test_create_snapshot_returns_snapshot(self) -> None:
        p = _make_persistence()
        state = _make_state()
        snapshot = p.create_snapshot(state)
        self.assertIsInstance(snapshot, ProjectStateSnapshot)
        self.assertEqual(snapshot.sequence, 1)
        self.assertIsNotNone(snapshot.snapshot_id)

    def test_create_snapshot_increments_sequence(self) -> None:
        p = _make_persistence()
        state = _make_state()
        s1 = p.create_snapshot(state)
        s2 = p.create_snapshot(state)
        self.assertEqual(s1.sequence, 1)
        self.assertEqual(s2.sequence, 2)

    def test_create_snapshot_preserves_state_fields(self) -> None:
        p = _make_persistence()
        state = _make_state(status="done", goal="Deploy Mindhub")
        snapshot = p.create_snapshot(state)
        self.assertEqual(snapshot.state.status, "done")
        self.assertEqual(snapshot.state.current_goal, "Deploy Mindhub")

    def test_create_snapshot_preserves_decisions(self) -> None:
        p = _make_persistence()
        state = _make_state()
        snapshot = p.create_snapshot(state)
        self.assertIn("use sqlite", snapshot.state.decisions)

    def test_create_snapshot_different_projects_independent(self) -> None:
        p = _make_persistence()
        s1 = p.create_snapshot(_make_state(project_id=1))
        s2 = p.create_snapshot(_make_state(project_id=2))
        self.assertEqual(s1.sequence, 1)
        self.assertEqual(s2.sequence, 1)


class TestSQLiteProjectStateCurrent(unittest.TestCase):
    def test_current_returns_none_for_unknown_project(self) -> None:
        p = _make_persistence()
        self.assertIsNone(p.current(999))

    def test_current_returns_latest_snapshot(self) -> None:
        p = _make_persistence()
        state1 = _make_state(status="started")
        state2 = _make_state(status="finished")
        p.create_snapshot(state1)
        p.create_snapshot(state2)
        current = p.current(1)
        self.assertIsNotNone(current)
        self.assertEqual(current.state.status, "finished")

    def test_current_snapshot_id_matches(self) -> None:
        p = _make_persistence()
        snapshot = p.create_snapshot(_make_state())
        current = p.current(1)
        self.assertEqual(current.snapshot_id, snapshot.snapshot_id)


class TestSQLiteProjectStateHistory(unittest.TestCase):
    def test_history_returns_empty_for_unknown_project(self) -> None:
        p = _make_persistence()
        self.assertEqual(p.history(999), ())

    def test_history_returns_all_snapshots_in_order(self) -> None:
        p = _make_persistence()
        p.create_snapshot(_make_state(status="step1"))
        p.create_snapshot(_make_state(status="step2"))
        p.create_snapshot(_make_state(status="step3"))
        history = p.history(1)
        self.assertEqual(len(history), 3)
        statuses = [s.state.status for s in history]
        self.assertEqual(statuses, ["step1", "step2", "step3"])

    def test_history_sequences_are_monotonic(self) -> None:
        p = _make_persistence()
        for _ in range(4):
            p.create_snapshot(_make_state())
        history = p.history(1)
        sequences = [s.sequence for s in history]
        self.assertEqual(sequences, sorted(sequences))


class TestSQLiteProjectStateFromEnv(unittest.TestCase):
    def test_from_env_uses_default_path(self) -> None:
        p = SQLiteProjectStatePersistence.from_env({}, default_path=":memory:")
        self.assertIsInstance(p, SQLiteProjectStatePersistence)

    def test_from_env_reads_env_var(self) -> None:
        p = SQLiteProjectStatePersistence.from_env({"MINDHUB_DB_PATH": ":memory:"})
        self.assertIsInstance(p, SQLiteProjectStatePersistence)


if __name__ == "__main__":
    unittest.main()
