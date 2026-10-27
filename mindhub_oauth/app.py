"""Starlette application factory for Mindhub OAuth facade."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from starlette.applications import Starlette
from starlette.routing import Route

from .config import Config
from .proxy import OAuthProxy
from .routes import OAuthRoutes
from .store import OAuthStore


def create_app(
    config: Config,
    store: OAuthStore | None = None,
    http_client: Any | None = None,
) -> Starlette:
    """Create and configure the Starlette application."""
    db_store = store if store is not None else OAuthStore(config.db_path)
    oauth_routes = OAuthRoutes(config, db_store)
    oauth_proxy = OAuthProxy(config, db_store, http_client=http_client)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncGenerator[None, None]:
        await oauth_proxy.start()
        try:
            yield
        finally:
            await oauth_proxy.aclose()
            db_store.close()

    routes = [
        Route("/health", oauth_routes.health, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource",
            oauth_routes.protected_resource_metadata,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            oauth_routes.protected_resource_metadata,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-authorization-server",
            oauth_routes.authorization_server_metadata,
            methods=["GET"],
        ),
        Route("/register", oauth_routes.register, methods=["POST"]),
        Route("/authorize", oauth_routes.authorize, methods=["GET"]),
        Route("/authorize/decision", oauth_routes.authorize_decision, methods=["POST"]),
        Route("/token", oauth_routes.token, methods=["POST"]),
        Route("/revoke", oauth_routes.revoke, methods=["POST"]),
        Route(
            "/mcp",
            oauth_proxy.handle_mcp,
            methods=["POST", "GET", "DELETE", "HEAD"],
        ),
    ]

    app = Starlette(routes=routes, lifespan=lifespan)
    # Store references for testing / introspection
    app.state.config = config
    app.state.store = db_store
    app.state.proxy = oauth_proxy
    app.state.http_client = http_client
    return app
