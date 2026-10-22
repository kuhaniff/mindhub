"""Entry point: python -m mindhub"""

from __future__ import annotations


def main() -> None:
    """Start the Mindhub MCP server using uvicorn."""
    import uvicorn
    from .server import create_app

    uvicorn.run(create_app(), host="0.0.0.0", port=8088, log_level="info")


if __name__ == "__main__":
    main()
