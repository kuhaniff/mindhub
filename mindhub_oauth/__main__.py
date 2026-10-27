"""CLI entry point: serve (default) and hash-password."""
from __future__ import annotations

import getpass
import sys
from typing import Sequence

import uvicorn

from .app import create_app
from .config import Config
from .security import hash_password


def hash_password_cli(args: Sequence[str]) -> None:
    """Prompt for password twice and print ONLY the scrypt hash line. Never accept password in argv."""
    if len(args) > 0:
        sys.stderr.write("Error: Passwords cannot be passed as command line arguments.\n")
        sys.exit(1)

    try:
        pw1 = getpass.getpass("Enter owner password: ")
        pw2 = getpass.getpass("Confirm owner password: ")
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\nAborted.\n")
        sys.exit(1)

    if pw1 != pw2:
        sys.stderr.write("Error: Passwords do not match.\n")
        sys.exit(1)

    if len(pw1) < 14:
        sys.stderr.write("Error: Password must be at least 14 characters.\n")
        sys.exit(1)

    h = hash_password(pw1)
    print(h)


def serve_cli(args: Sequence[str]) -> None:
    """Start uvicorn server with Config from environment."""
    cfg = Config.from_env()
    app = create_app(cfg)
    uvicorn.run(
        app,
        host=cfg.host,
        port=cfg.port,
        log_level="info",
        proxy_headers=False,
        server_header=False,
        date_header=True,
        access_log=False,
        lifespan="on",
        timeout_graceful_shutdown=5,
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "serve"
    cmd_args = args[1:] if args else []

    if cmd == "hash-password":
        hash_password_cli(cmd_args)
    elif cmd == "serve":
        serve_cli(cmd_args)
    else:
        sys.stderr.write(f"Unknown command: {cmd}. Available: serve, hash-password\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
