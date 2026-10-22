"""Standalone Mindhub MCP server.

Run with:  python -m mindhub
Or via entry point:  mindhub-server
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as _mcp_err:  # pragma: no cover
    raise ImportError(
        "mcp package is required for the server module. "
        "Install it with: pip install 'mcp>=2.3.0'"
    ) from _mcp_err

from .memory import (
    MemoryPersistenceError,
    MemoryPersistence,
    remember_memory,
    search_memories,
)
from .project_state import (
    ProjectStatePersistence,
    ProjectStateNotFoundError,
    ProjectStatePersistenceError,
    get_project_state as _get_state,
    get_project_state_history as _get_history,
    update_project_state as _update_state,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton backends (lazy init from env, overridable via create_app)
# ---------------------------------------------------------------------------

_memory_backend: MemoryPersistence | None = None
_state_backend: ProjectStatePersistence | None = None


def _get_memory_backend() -> MemoryPersistence:
    global _memory_backend
    if _memory_backend is None:
        from .sqlite_memory import SQLiteMemoryPersistence
        _memory_backend = SQLiteMemoryPersistence.from_env()
    return _memory_backend


def _get_state_backend() -> ProjectStatePersistence:
    global _state_backend
    if _state_backend is None:
        from .sqlite_project_state import SQLiteProjectStatePersistence
        _state_backend = SQLiteProjectStatePersistence.from_env()
    return _state_backend


# ---------------------------------------------------------------------------
# FastMCP instance and tool registrations
# ---------------------------------------------------------------------------

mcp = FastMCP("mindhub")


@mcp.tool()
def search_memory(query: str, limit: int = 10) -> list[dict]:
    """Search memories by content substring."""
    try:
        return search_memories(_get_memory_backend(), query, limit=limit)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    except MemoryPersistenceError as exc:
        logger.error("memory search persistence error: %s", exc)
        raise


@mcp.tool()
def remember(
    content: str,
    memory_type: str = "fact",
    source: str | None = None,
    project_id: int | None = None,
) -> dict:
    """Store a new memory and return the persisted record."""
    try:
        return remember_memory(
            _get_memory_backend(),
            content,
            memory_type=memory_type,
            source=source,
            project_id=project_id,
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    except MemoryPersistenceError as exc:
        logger.error("memory store persistence error: %s", exc)
        raise


@mcp.tool()
def get_project_state(project_id: int) -> dict:
    """Retrieve the current project state for the given project_id."""
    try:
        return _get_state(_get_state_backend(), project_id)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    except ProjectStateNotFoundError as exc:
        raise LookupError(str(exc)) from exc
    except ProjectStatePersistenceError as exc:
        logger.error("project state read persistence error: %s", exc)
        raise


@mcp.tool()
def update_project_state(project_id: int, state: dict) -> dict:
    """Create a new snapshot of the project state."""
    try:
        return _update_state(_get_state_backend(), project_id, state)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    except ProjectStatePersistenceError as exc:
        logger.error("project state update persistence error: %s", exc)
        raise


@mcp.tool()
def get_project_state_history(project_id: int) -> list[dict]:
    """Retrieve the full snapshot history for the given project_id."""
    try:
        return _get_history(_get_state_backend(), project_id)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    except ProjectStatePersistenceError as exc:
        logger.error("project state history persistence error: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------


class _APIKeyMiddleware(BaseHTTPMiddleware):
    """Reject requests missing a valid X-API-Key header (except /health)."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path == "/health":
            return await call_next(request)

        raw = os.environ.get("MINDHUB_API_KEYS", "")
        valid_keys = {k.strip() for k in raw.split(",") if k.strip()}
        if not valid_keys:
            return Response(
                content='{"detail":"service not configured"}',
                status_code=401,
                media_type="application/json",
            )

        provided = request.headers.get("X-API-Key", "")
        if provided not in valid_keys:
            return Response(
                content='{"detail":"invalid or missing API key"}',
                status_code=401,
                media_type="application/json",
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    memory_backend: MemoryPersistence | None = None,
    state_backend: ProjectStatePersistence | None = None,
) -> FastAPI:
    """Create and return a FastAPI application with the MCP server mounted.

    Args:
        memory_backend: Optional pre-built memory persistence backend.
            If None, one will be created lazily from environment variables.
        state_backend: Optional pre-built project state persistence backend.
            If None, one will be created lazily from environment variables.

    Returns:
        A configured FastAPI application instance.
    """
    global _memory_backend, _state_backend

    if memory_backend is not None:
        _memory_backend = memory_backend
    if state_backend is not None:
        _state_backend = state_backend

    app = FastAPI(title="Mindhub MCP Server", version="0.1.0")

    # Health endpoint (excluded from auth)
    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "mindhub"}

    # Auth middleware
    app.add_middleware(_APIKeyMiddleware)

    # Mount MCP ASGI app
    try:
        mcp_asgi = mcp.streamable_http_app()
    except AttributeError:
        try:
            mcp_asgi = mcp.get_asgi_app()
        except AttributeError as exc:  # pragma: no cover
            raise RuntimeError(
                "FastMCP does not expose a compatible ASGI app method. "
                "Upgrade to mcp>=2.3.0."
            ) from exc

    app.mount("/mcp", mcp_asgi)

    return app


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=8088, log_level="info")
