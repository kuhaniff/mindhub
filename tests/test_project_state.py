from datetime import datetime, timezone
import unittest

from mindhub.project_state import ProjectState, ProjectStateStore


class ProjectStateTests(unittest.TestCase):
    def state(self, **changes):
        values = {
            "project_id": 7,
            "current_goal": "Validate MCP adapter",
            "status": "in_progress",
            "progress": "Local handshake tests pass",
            "decisions": ("Use the existing gateway",),
            "blockers": ("Production endpoint is not verified",),
            "next_action": "Confirm endpoint safely",
            "updated_at": datetime(2026, 10, 14, tzinfo=timezone.utc),
        }
        values.update(changes)
        return ProjectState(**values)

    def test_store_returns_current_state_for_a_project(self):
        store = ProjectStateStore()
        state = self.state()

        store.update(state)

        self.assertEqual(store.current(7), state)

    def test_update_preserves_previous_state_in_history(self):
        store = ProjectStateStore()
        first = self.state(status="planned", progress="Not started")
        second = self.state(
            status="in_progress",
            progress="Adapter implemented",
            updated_at=datetime(2026, 10, 15, tzinfo=timezone.utc),
        )

        store.update(first)
        store.update(second)

        self.assertEqual(store.current(7), second)
        self.assertEqual(store.history(7), (first, second))

    def test_projects_have_separate_state_and_history(self):
        store = ProjectStateStore()
        store.update(self.state(project_id=7))
        store.update(self.state(project_id=8, current_goal="Review backup plan"))

        self.assertEqual(store.current(7).current_goal, "Validate MCP adapter")
        self.assertEqual(store.current(8).current_goal, "Review backup plan")
        self.assertEqual(len(store.history(7)), 1)
        self.assertEqual(len(store.history(8)), 1)

    def test_unknown_project_has_no_current_state(self):
        store = ProjectStateStore()

        self.assertIsNone(store.current(999))
        self.assertEqual(store.history(999), ())

    def test_state_rejects_invalid_required_fields(self):
        with self.assertRaises(ValueError):
            self.state(project_id=0)
        with self.assertRaises(ValueError):
            self.state(current_goal=" ")
        with self.assertRaises(ValueError):
            self.state(status="")
        with self.assertRaises(ValueError):
            self.state(updated_at=datetime(2026, 10, 14))


if __name__ == "__main__":
    unittest.main()
