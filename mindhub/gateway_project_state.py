"""Gateway-facing Project State tool registration.

The real gateway can pass its MCPServer instance and a persistence backend to
``register_project_state_tools``. This module deliberately does not construct
an application, alter authentication, or connect to a database at import time.
"""

from __future__ import annotations

from typing import Mapping

from .mysql_project_state import MySQLProjectStatePersistence
from .project_state import (
    ProjectStateNotFoundError,
    ProjectStatePersistence,
    ProjectStatePersistenceError,
    get_project_state as get_project_state_handler,
    get_project_state_history as get_project_state_history_handler,
    update_project_state as update_project_state_handler,
)


def register_project_state_tools(mcp_server: object, persistence: ProjectStatePersistence) -> tuple:
    """Register the three tools using the gateway's existing decorator API."""

    get_state = get_project_state_handler
    get_history = get_project_state_history_handler
    update_state = update_project_state_handler

    @mcp_server.tool()
    def get_project_state(project_id: int) -> dict:
        try:
            return get_state(persistence, project_id)
        except ProjectStatePersistenceError:
            raise RuntimeError("Project State database unavailable") from None
        except ProjectStateNotFoundError:
            raise

    @mcp_server.tool()
    def update_project_state(project_id: int, state: dict) -> dict:
        try:
            return update_state(persistence, project_id, state)
        except ProjectStatePersistenceError:
            raise RuntimeError("Project State database unavailable") from None

    @mcp_server.tool()
    def get_project_state_history(project_id: int) -> list[dict]:
        try:
            return get_history(persistence, project_id)
        except ProjectStatePersistenceError:
            raise RuntimeError("Project State database unavailable") from None

    return get_project_state, update_project_state, get_project_state_history


def persistence_from_environment() -> MySQLProjectStatePersistence:
    """Build the backend from existing MYSQL_* environment settings."""
    return MySQLProjectStatePersistence.from_env()
