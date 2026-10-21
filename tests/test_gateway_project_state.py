import unittest

from mindhub.gateway_project_state import register_project_state_tools
from mindhub.project_state import (
    InMemoryProjectStatePersistence,
    ProjectStateNotFoundError,
    ProjectStatePersistenceError,
)


class FakeMCPServer:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorator(function):
            self.tools[function.__name__] = function
            return function
        return decorator


class FailingPersistence(InMemoryProjectStatePersistence):
    def create_snapshot(self, state):
        raise ProjectStatePersistenceError("synthetic failure")


class GatewayProjectStateRegistrationTests(unittest.TestCase):
    def state(self, **changes):
        value = {
            "current_goal": "Integrate Project State",
            "status": "in_progress",
            "progress": "Handler wiring",
            "decisions": ["Preserve existing tools"],
            "blockers": [],
            "next_action": "Run gateway tests",
        }
        value.update(changes)
        return value

    def test_registers_exactly_the_three_project_state_tools(self):
        server = FakeMCPServer()
        registered = register_project_state_tools(server, InMemoryProjectStatePersistence())

        self.assertEqual(
            set(server.tools),
            {"get_project_state", "update_project_state", "get_project_state_history"},
        )
        self.assertEqual(
            {function.__name__ for function in registered},
            set(server.tools),
        )

    def test_handlers_preserve_current_history_and_isolation(self):
        server = FakeMCPServer()
        register_project_state_tools(server, InMemoryProjectStatePersistence())

        first = server.tools["update_project_state"](7, self.state())
        second = server.tools["update_project_state"](7, self.state(progress="Registered"))
        other = server.tools["update_project_state"](8, self.state(current_goal="Other project"))

        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(other["project_id"], 8)
        self.assertEqual(server.tools["get_project_state"](7), second)
        self.assertEqual(
            [item["sequence"] for item in server.tools["get_project_state_history"](7)],
            [1, 2],
        )

    def test_handlers_validate_input_and_not_found(self):
        server = FakeMCPServer()
        register_project_state_tools(server, InMemoryProjectStatePersistence())

        with self.assertRaises(ValueError):
            server.tools["get_project_state"](0)
        with self.assertRaises(ValueError):
            server.tools["update_project_state"](7, {"status": "planned"})
        with self.assertRaises(ValueError):
            server.tools["update_project_state"](7, self.state(snapshot_id="client-id"))
        with self.assertRaises(ProjectStateNotFoundError):
            server.tools["get_project_state"](99)

    def test_persistence_failure_is_safe(self):
        server = FakeMCPServer()
        register_project_state_tools(server, FailingPersistence())

        with self.assertRaises(RuntimeError) as caught:
            server.tools["update_project_state"](7, self.state())
        self.assertEqual(str(caught.exception), "Project State database unavailable")


if __name__ == "__main__":
    unittest.main()
