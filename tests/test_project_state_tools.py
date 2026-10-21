from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import unittest

from mindhub.project_state import (
    InMemoryProjectStatePersistence,
    ProjectStatePersistenceError,
    ProjectStateNotFoundError,
    get_project_state,
    get_project_state_history,
    update_project_state,
)


class FailingPersistence(InMemoryProjectStatePersistence):
    def create_snapshot(self, state):
        raise ProjectStatePersistenceError("synthetic persistence failure")


class ProjectStateToolTests(unittest.TestCase):
    def state(self, **changes):
        value = {
            "current_goal": "Validate Project State",
            "status": "in_progress",
            "progress": "Local implementation",
            "decisions": ["Keep snapshots immutable"],
            "blockers": ["Production schema is not verified"],
            "next_action": "Review backend contract",
        }
        value.update(changes)
        return value

    def test_update_get_and_history_return_backend_metadata(self):
        store = InMemoryProjectStatePersistence()

        first = update_project_state(store, 7, self.state())
        second = update_project_state(store, 7, self.state(progress="Tests pass"))

        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(get_project_state(store, 7), second)
        self.assertEqual(
            [item["sequence"] for item in get_project_state_history(store, 7)],
            [1, 2],
        )

    def test_history_is_isolated_per_project(self):
        store = InMemoryProjectStatePersistence()
        update_project_state(store, 7, self.state())
        update_project_state(store, 8, self.state(current_goal="Other project"))

        self.assertEqual(get_project_state(store, 7)["project_id"], 7)
        self.assertEqual(get_project_state(store, 8)["project_id"], 8)
        self.assertEqual(len(get_project_state_history(store, 7)), 1)
        self.assertEqual(len(get_project_state_history(store, 8)), 1)

    def test_missing_state_is_not_found_and_history_is_empty(self):
        store = InMemoryProjectStatePersistence()

        with self.assertRaises(ProjectStateNotFoundError):
            get_project_state(store, 999)
        self.assertEqual(get_project_state_history(store, 999), [])

    def test_validation_rejects_invalid_project_and_client_metadata(self):
        store = InMemoryProjectStatePersistence()
        with self.assertRaises(ValueError):
            update_project_state(store, 0, self.state())
        with self.assertRaises(ValueError):
            update_project_state(store, 7, self.state(current_goal=""))
        with self.assertRaises(ValueError):
            update_project_state(store, 7, self.state(snapshot_id="client-id"))
        with self.assertRaises(ValueError):
            update_project_state(store, 7, self.state(sequence=99))
        with self.assertRaises(ValueError):
            update_project_state(store, 7, self.state(current_goal=42))
        with self.assertRaises(ValueError):
            update_project_state(store, 7, self.state(next_action=42))

    def test_concurrent_updates_get_unique_monotonic_sequences(self):
        store = InMemoryProjectStatePersistence()

        def update(index):
            return update_project_state(store, 7, self.state(progress=f"step {index}"))

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(update, range(20)))

        sequences = sorted(item["sequence"] for item in results)
        self.assertEqual(sequences, list(range(1, 21)))
        self.assertEqual(get_project_state(store, 7)["sequence"], 20)
        self.assertEqual(len(get_project_state_history(store, 7)), 20)

    def test_persistence_failure_does_not_create_state(self):
        store = FailingPersistence()
        with self.assertRaises(ProjectStatePersistenceError):
            update_project_state(store, 7, self.state())
        self.assertEqual(store.history(7), ())

    def test_updated_at_is_generated_when_not_provided(self):
        store = InMemoryProjectStatePersistence()
        result = update_project_state(store, 7, self.state())
        parsed = datetime.fromisoformat(result["updated_at"])
        self.assertIsNotNone(parsed.tzinfo)


if __name__ == "__main__":
    unittest.main()
