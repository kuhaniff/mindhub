"""HTTP client compatibility module."""
from __future__ import annotations

try:
    import httpx
except ImportError:
    import httpx2 as httpx  # type: ignore[no-redef]

__all__ = ["httpx"]
