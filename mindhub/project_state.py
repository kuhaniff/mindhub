"""Local Project State model, persistence contract and MCP-style handlers.

This module is local-only. It does not define or assume a production database
schema, migration, endpoint or gateway runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Mapping, Protocol
from uuid import uuid4


class ProjectStateNotFoundError(LookupError):
    """No current state exists for the requested project."""


class ProjectStatePersistenceError(RuntimeError):
    """Persistence failed before a snapshot was committed."""


@dataclass(frozen=True)
class ProjectState:
    """Client-provided state payload without backend metadata."""

    project_id: int
    current_goal: str
    status: str
    progress: str
    updated_at: datetime
    decisions: tuple[str, ...] = field(default_factory=tuple)
    blockers: tuple[str, ...] = field(default_factory=tuple)
    next_action: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.project_id, bool) or not isinstance(self.project_id, int) or self.project_id <= 0:
            raise ValueError("project_id must be greater than zero")
        if not isinstance(self.current_goal, str) or not self.current_goal.strip():
            raise ValueError("current_goal cannot be empty")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("status cannot be empty")
        if not isinstance(self.progress, str) or not self.progress.strip():
            raise ValueError("progress cannot be empty")
        if not isinstance(self.updated_at, datetime) or self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise ValueError("updated_at must be timezone-aware")
        if not all(isinstance(item, str) and item.strip() for item in self.decisions):
            raise ValueError("decisions must contain non-empty strings")
        if not all(isinstance(item, str) and item.strip() for item in self.blockers):
            raise ValueError("blockers must contain non-empty strings")
        if self.next_action is not None and (
            not isinstance(self.next_action, str) or not self.next_action.strip()
        ):
            raise ValueError("next_action cannot be empty")
        object.__setattr__(self, "decisions", tuple(self.decisions))
        object.__setattr__(self, "blockers", tuple(self.blockers))


@dataclass(frozen=True)
class ProjectStateSnapshot:
    """Immutable backend-generated snapshot."""

    snapshot_id: str
    sequence: int
    state: ProjectState

    def as_dict(self) -> dict:
        return {
            "project_id": self.state.project_id,
            "snapshot_id": self.snapshot_id,
            "sequence": self.sequence,
            "current_goal": self.state.current_goal,
            "status": self.state.status,
            "progress": self.state.progress,
            "decisions": list(self.state.decisions),
            "blockers": list(self.state.blockers),
            "next_action": self.state.next_action,
            "updated_at": self.state.updated_at.isoformat(),
        }


class ProjectStatePersistence(Protocol):
    """Persistence contract required by the handlers."""

    def create_snapshot(self, state: ProjectState) -> ProjectStateSnapshot:
        ...

    def current(self, project_id: int) -> ProjectStateSnapshot | None:
        ...

    def history(self, project_id: int) -> tuple[ProjectStateSnapshot, ...]:
        ...


class InMemoryProjectStatePersistence:
    """Thread-safe fake persistence with atomic snapshot publication."""

    def __init__(self) -> None:
        self._history: dict[int, list[ProjectStateSnapshot]] = {}
        self._current: dict[int, ProjectStateSnapshot] = {}
        self._sequence: dict[int, int] = {}
        self._lock = RLock()

    def create_snapshot(self, state: ProjectState) -> ProjectStateSnapshot:
        with self._lock:
            sequence = self._sequence.get(state.project_id, 0) + 1
            snapshot = ProjectStateSnapshot(
                snapshot_id=str(uuid4()),
                sequence=sequence,
                state=state,
            )
            self._history.setdefault(state.project_id, []).append(snapshot)
            self._sequence[state.project_id] = sequence
            self._current[state.project_id] = snapshot
            return snapshot

    def current(self, project_id: int) -> ProjectStateSnapshot | None:
        with self._lock:
            return self._current.get(project_id)

    def history(self, project_id: int) -> tuple[ProjectStateSnapshot, ...]:
        with self._lock:
            return tuple(self._history.get(project_id, ()))


class ProjectStateStore:
    """Compatibility facade for the original local state-only API."""

    def __init__(self) -> None:
        self._backend = InMemoryProjectStatePersistence()

    def update(self, state: ProjectState) -> ProjectStateSnapshot:
        return self._backend.create_snapshot(state)

    def current(self, project_id: int) -> ProjectState | None:
        snapshot = self._backend.current(project_id)
        return snapshot.state if snapshot is not None else None

    def history(self, project_id: int) -> tuple[ProjectState, ...]:
        return tuple(snapshot.state for snapshot in self._backend.history(project_id))


def _validate_project_id(project_id: int) -> None:
    if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
        raise ValueError("project_id must be greater than zero")


def _state_from_payload(project_id: int, payload: Mapping[str, object]) -> ProjectState:
    forbidden = {"snapshot_id", "sequence", "updated_at"}.intersection(payload)
    if forbidden:
        raise ValueError("backend metadata cannot be supplied by the client")

    required = {"current_goal", "status", "progress"}
    missing = required.difference(payload)
    if missing:
        raise ValueError("missing required project state fields")

    decisions = payload.get("decisions", ())
    blockers = payload.get("blockers", ())
    if not isinstance(decisions, (list, tuple)):
        raise ValueError("decisions must be a list")
    if not isinstance(blockers, (list, tuple)):
        raise ValueError("blockers must be a list")

    return ProjectState(
        project_id=project_id,
        current_goal=payload["current_goal"],  # type: ignore[arg-type]
        status=payload["status"],  # type: ignore[arg-type]
        progress=payload["progress"],  # type: ignore[arg-type]
        decisions=tuple(decisions),  # type: ignore[arg-type]
        blockers=tuple(blockers),  # type: ignore[arg-type]
        next_action=payload.get("next_action"),  # type: ignore[arg-type]
        updated_at=datetime.now(timezone.utc),
    )


def get_project_state(
    persistence: ProjectStatePersistence,
    project_id: int,
) -> dict:
    _validate_project_id(project_id)
    snapshot = persistence.current(project_id)
    if snapshot is None:
        raise ProjectStateNotFoundError(f"project {project_id} has no state")
    return snapshot.as_dict()


def update_project_state(
    persistence: ProjectStatePersistence,
    project_id: int,
    state: Mapping[str, object],
) -> dict:
    _validate_project_id(project_id)
    if not isinstance(state, Mapping):
        raise ValueError("state must be an object")
    payload = _state_from_payload(project_id, state)
    return persistence.create_snapshot(payload).as_dict()


def get_project_state_history(
    persistence: ProjectStatePersistence,
    project_id: int,
) -> list[dict]:
    _validate_project_id(project_id)
    return [snapshot.as_dict() for snapshot in persistence.history(project_id)]
