"""mindhub local MCP adapter package."""

from .mcp_adapter import (
    MCPAuthenticationError,
    MCPError,
    MCPToolError,
    MCPTransportError,
    StreamableHTTPMCPClient,
    extract_tool_payload,
)
from .migrations import (
    apply_migrations,
    get_migration_sql,
    run_migration_from_env,
)
from .project_state import (
    InMemoryProjectStatePersistence,
    ProjectState,
    ProjectStateNotFoundError,
    ProjectStatePersistence,
    ProjectStatePersistenceError,
    ProjectStateSnapshot,
    ProjectStateStore,
    get_project_state,
    get_project_state_history,
    update_project_state,
)
from .wiki_sync import (
    WikiPage,
    WikiSync,
    WikiSyncConfig,
    WikiSyncResult,
)

__all__ = [
    "InMemoryProjectStatePersistence",
    "MCPAuthenticationError",
    "MCPError",
    "MCPToolError",
    "MCPTransportError",
    "ProjectState",
    "ProjectStateNotFoundError",
    "ProjectStatePersistence",
    "ProjectStatePersistenceError",
    "ProjectStateSnapshot",
    "ProjectStateStore",
    "StreamableHTTPMCPClient",
    "WikiPage",
    "WikiSync",
    "WikiSyncConfig",
    "WikiSyncResult",
    "apply_migrations",
    "extract_tool_payload",
    "get_migration_sql",
    "get_project_state",
    "get_project_state_history",
    "run_migration_from_env",
    "update_project_state",
]
