"""GitHub Wiki to MCP memory one-way synchronization tool."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

logger = logging.getLogger(__name__)

# Patterns for sensitive credentials that should not be stored in memory
SECRET_PATTERNS = [
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    re.compile(r"glpat-[a-zA-Z0-9\-]{20}"),
    re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{16,}"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"),
]

DEFAULT_DENYLIST = ("_Sidebar.md", "_Footer.md")


def redact_sensitive_content(content: str) -> str:
    """Detect and redact potential secrets from markdown content."""
    sanitized = content
    for pattern in SECRET_PATTERNS:
        def _replace(match: re.Match) -> str:
            # If pattern captured a specific secret group, replace that group
            full = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                secret_part = match.group(1)
                return full.replace(secret_part, "[REDACTED_SECRET]")
            return "[REDACTED_SECRET]"

        sanitized = pattern.sub(_replace, sanitized)
    return sanitized


def extract_page_title(content: str, fallback: str) -> str:
    """Extract page title from markdown heading or fallback to file name."""
    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("# "):
            title = trimmed[2:].strip()
            if title:
                return title
    return fallback


def slugify(text: str) -> str:
    """Convert heading text to URL anchor slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[-\s]+", "-", text).strip("-")


@dataclass(frozen=True)
class WikiChunk:
    source: str
    content: str
    title: str
    checksum: str


@dataclass
class WikiPage:
    path: Path
    relative_path: str
    title: str
    raw_content: str


@dataclass
class WikiSyncConfig:
    wiki_dir: Path
    allowlist: tuple[str, ...] | None = None
    denylist: tuple[str, ...] = DEFAULT_DENYLIST
    max_chunk_chars: int = 4000
    memory_type: str = "wiki"
    dry_run: bool = False
    manifest_path: Path | None = None
    redact_secrets: bool = True

    def __post_init__(self):
        self.wiki_dir = Path(self.wiki_dir).resolve()
        if self.manifest_path is None:
            self.manifest_path = self.wiki_dir / ".wiki_sync_manifest.json"
        else:
            self.manifest_path = Path(self.manifest_path).resolve()


@dataclass
class WikiSyncResult:
    scanned: int = 0
    synced: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    items: list[dict[str, Any]] = field(default_factory=list)


def split_page_into_chunks(page: WikiPage, max_chunk_chars: int) -> list[WikiChunk]:
    """Split a wiki page into coherent chunks by headings or keep single chunk."""
    content = page.raw_content.strip()
    if not content:
        return []

    # If document fits within max_chunk_chars, return as a single chunk
    if len(content) <= max_chunk_chars:
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()
        source = f"wiki:{page.relative_path}"
        header = f"# [Wiki] {page.title} ({page.relative_path})\n\n"
        formatted_content = content if content.startswith("# ") else header + content
        return [WikiChunk(source=source, content=formatted_content, title=page.title, checksum=checksum)]

    # Otherwise, split by H2/H3 markdown headings
    sections = re.split(r"(?m)(?=^##\s+)", content)
    chunks: list[WikiChunk] = []

    for section in sections:
        sec_text = section.strip()
        if not sec_text:
            continue

        # Determine section title & slug
        first_line = sec_text.splitlines()[0]
        if first_line.startswith("## "):
            sec_title = first_line[3:].strip()
            anchor = slugify(sec_title)
            source = f"wiki:{page.relative_path}#{anchor}"
            chunk_title = f"{page.title} - {sec_title}"
        else:
            sec_title = page.title
            source = f"wiki:{page.relative_path}"
            chunk_title = page.title

        formatted_chunk = f"# [Wiki] {chunk_title} ({page.relative_path})\n\n{sec_text}"
        checksum = hashlib.sha256(sec_text.encode("utf-8")).hexdigest()
        chunks.append(WikiChunk(source=source, content=formatted_chunk, title=chunk_title, checksum=checksum))

    return chunks


class WikiSync:
    """Manages one-way synchronization of GitHub Wiki markdown files into MCP memory."""

    def __init__(self, client: Any, config: WikiSyncConfig) -> None:
        self.client = client
        self.config = config

    def scan_pages(self) -> list[WikiPage]:
        """Scan wiki directory for markdown files according to allowlist and denylist."""
        if not self.config.wiki_dir.exists():
            raise FileNotFoundError(f"Wiki directory does not exist: {self.config.wiki_dir}")

        pages: list[WikiPage] = []
        for root, dirs, files in os.walk(self.config.wiki_dir):
            # Skip hidden directories (.git, etc.)
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for file in files:
                if file.startswith("."):
                    continue
                if not file.lower().endswith(".md"):
                    continue

                full_path = Path(root) / file
                rel_path = str(full_path.relative_to(self.config.wiki_dir)).replace("\\", "/")

                # Check denylist
                if any(fnmatch.fnmatch(file, pattern) or fnmatch.fnmatch(rel_path, pattern) for pattern in self.config.denylist):
                    continue

                # Check allowlist if specified
                if self.config.allowlist is not None:
                    matched = any(
                        fnmatch.fnmatch(file, pattern) or fnmatch.fnmatch(rel_path, pattern)
                        for pattern in self.config.allowlist
                    )
                    if not matched:
                        continue

                try:
                    content = full_path.read_text(encoding="utf-8")
                except Exception as exc:
                    logger.warning("Could not read file %s: %s", full_path, exc)
                    continue

                if self.config.redact_secrets:
                    content = redact_sensitive_content(content)

                fallback_title = full_path.stem.replace("-", " ").replace("_", " ").title()
                title = extract_page_title(content, fallback=fallback_title)
                pages.append(WikiPage(path=full_path, relative_path=rel_path, title=title, raw_content=content))

        # Sort for deterministic processing
        pages.sort(key=lambda p: p.relative_path)
        return pages

    def load_manifest(self) -> dict[str, str]:
        """Load manifest mapping chunk source -> sha256 checksum."""
        if self.config.manifest_path and self.config.manifest_path.exists():
            try:
                data = json.loads(self.config.manifest_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception as exc:
                logger.warning("Could not read manifest file %s: %s", self.config.manifest_path, exc)
        return {}

    def save_manifest(self, manifest: dict[str, str]) -> None:
        """Save manifest mapping chunk source -> sha256 checksum."""
        if self.config.manifest_path:
            try:
                self.config.manifest_path.parent.mkdir(parents=True, exist_ok=True)
                self.config.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
            except Exception as exc:
                logger.warning("Could not write manifest file %s: %s", self.config.manifest_path, exc)

    def sync(self, force: bool = False) -> WikiSyncResult:
        """Execute one-way sync into MCP memory."""
        pages = self.scan_pages()
        manifest = self.load_manifest()
        new_manifest = dict(manifest)
        result = WikiSyncResult(scanned=len(pages))

        for page in pages:
            chunks = split_page_into_chunks(page, self.config.max_chunk_chars)
            for chunk in chunks:
                cached_checksum = manifest.get(chunk.source)
                if not force and cached_checksum == chunk.checksum:
                    result.skipped += 1
                    result.items.append({"source": chunk.source, "status": "skipped", "title": chunk.title})
                    continue

                if self.config.dry_run:
                    result.synced += 1
                    result.items.append({"source": chunk.source, "status": "would_sync", "title": chunk.title})
                    continue

                try:
                    self.client.remember(
                        content=chunk.content,
                        memory_type=self.config.memory_type,
                        source=chunk.source,
                    )
                    new_manifest[chunk.source] = chunk.checksum
                    result.synced += 1
                    result.items.append({"source": chunk.source, "status": "synced", "title": chunk.title})
                except Exception as exc:
                    err_msg = f"Failed to sync chunk {chunk.source}: {exc}"
                    logger.error(err_msg)
                    result.errors.append(err_msg)
                    result.items.append({"source": chunk.source, "status": "error", "error": str(exc)})

        if not self.config.dry_run:
            self.save_manifest(new_manifest)

        return result


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for wiki sync."""
    parser = argparse.ArgumentParser(description="Synchronize GitHub Wiki documentation into Mindhub MCP memory.")
    parser.add_argument("--wiki-dir", required=True, type=Path, help="Path to local wiki directory or cloned git repo.")
    parser.add_argument("--endpoint", default=os.environ.get("MINDHUB_MCP_ENDPOINT", "http://127.0.0.1:8087/mcp"), help="MCP endpoint URL.")
    parser.add_argument("--api-key", default=os.environ.get("MINDHUB_API_KEY", ""), help="MCP API Key.")
    parser.add_argument("--allowlist", help="Comma-separated allowlist of file names/patterns.")
    parser.add_argument("--dry-run", action="store_true", help="Scan and simulate sync without writing to memory.")
    parser.add_argument("--force", action="store_true", help="Force re-sync even if unchanged in manifest.")
    parser.add_argument("--manifest", type=Path, help="Path to sync manifest file.")

    args = parser.parse_args(argv)

    if not args.dry_run and not args.api_key:
        print("Error: --api-key or MINDHUB_API_KEY environment variable is required unless --dry-run is set.")
        return 1

    allowlist = tuple(p.strip() for p in args.allowlist.split(",") if p.strip()) if args.allowlist else None

    config = WikiSyncConfig(
        wiki_dir=args.wiki_dir,
        allowlist=allowlist,
        dry_run=args.dry_run,
        manifest_path=args.manifest,
    )

    client = None
    if not args.dry_run:
        from .mcp_adapter import StreamableHTTPMCPClient
        client = StreamableHTTPMCPClient(args.endpoint, api_key=args.api_key)
        client.initialize()

    syncer = WikiSync(client, config)
    res = syncer.sync(force=args.force)

    print(f"Sync complete: {res.scanned} pages scanned, {res.synced} chunks synced, {res.skipped} skipped, {len(res.errors)} errors.")
    return 0 if not res.errors else 2


if __name__ == "__main__":
    import sys
    sys.exit(main())
