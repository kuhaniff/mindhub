import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

from mindhub.wiki_sync import (
    WikiPage,
    WikiSync,
    WikiSyncConfig,
    WikiSyncResult,
    extract_page_title,
    redact_sensitive_content,
)


class WikiSyncUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.wiki_path = Path(self.temp_dir.name)

        # Create sample wiki files
        (self.wiki_path / "Home.md").write_text("# Homelab Overview\nWelcome to homelab wiki.", encoding="utf-8")
        (self.wiki_path / "Architecture.md").write_text("# Architecture Guide\nDetails about services.", encoding="utf-8")
        (self.wiki_path / "_Sidebar.md").write_text("* [[Home]]\n* [[Architecture]]", encoding="utf-8")
        (self.wiki_path / "_Footer.md").write_text("Copyright 2026", encoding="utf-8")
        (self.wiki_path / "diagram.png").write_bytes(b"PNGDATA")
        hidden = self.wiki_path / ".secret"
        hidden.mkdir()
        (hidden / "notes.md").write_text("hidden", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extract_page_title_from_heading(self):
        title = extract_page_title("# My Cool Page\nContent here", fallback="fallback")
        self.assertEqual(title, "My Cool Page")

    def test_extract_page_title_fallback(self):
        title = extract_page_title("No header here\nJust text", fallback="PageName")
        self.assertEqual(title, "PageName")

    def test_redact_sensitive_content(self):
        raw = "My token is ghp_123456789012345678901234567890123456 and api_key = 'super_secret_val_123'"
        sanitized = redact_sensitive_content(raw)
        self.assertNotIn("ghp_123456789012345678901234567890123456", sanitized)
        self.assertNotIn("super_secret_val_123", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)

    def test_scan_pages_filters_denylist_and_non_markdown(self):
        mock_client = MagicMock()
        config = WikiSyncConfig(wiki_dir=self.wiki_path)
        syncer = WikiSync(mock_client, config)

        pages = syncer.scan_pages()
        names = [p.relative_path for p in pages]

        self.assertIn("Home.md", names)
        self.assertIn("Architecture.md", names)
        self.assertNotIn("_Sidebar.md", names)
        self.assertNotIn("_Footer.md", names)
        self.assertNotIn("diagram.png", names)
        self.assertFalse(any(n.startswith(".") for n in names))

    def test_scan_pages_with_allowlist(self):
        mock_client = MagicMock()
        config = WikiSyncConfig(wiki_dir=self.wiki_path, allowlist=("Home.md",))
        syncer = WikiSync(mock_client, config)

        pages = syncer.scan_pages()
        names = [p.relative_path for p in pages]

        self.assertEqual(names, ["Home.md"])

    def test_sync_dry_run_does_not_call_remember(self):
        mock_client = MagicMock()
        config = WikiSyncConfig(wiki_dir=self.wiki_path, dry_run=True)
        syncer = WikiSync(mock_client, config)

        result = syncer.sync()

        self.assertEqual(result.scanned, 2)
        self.assertEqual(result.synced, 2)
        mock_client.remember.assert_not_called()

    def test_sync_calls_remember_with_expected_payload(self):
        mock_client = MagicMock()
        mock_client.remember.return_value = {"id": 101, "status": "saved"}
        config = WikiSyncConfig(wiki_dir=self.wiki_path, dry_run=False)
        syncer = WikiSync(mock_client, config)

        result = syncer.sync()

        self.assertEqual(result.scanned, 2)
        self.assertEqual(result.synced, 2)
        self.assertEqual(mock_client.remember.call_count, 2)

        calls = mock_client.remember.call_args_list
        sources = [c.kwargs.get("source") for c in calls]
        self.assertIn("wiki:Home.md", sources)
        self.assertIn("wiki:Architecture.md", sources)

    def test_sync_skips_unchanged_files_via_manifest(self):
        mock_client = MagicMock()
        mock_client.remember.return_value = {"id": 101, "status": "saved"}
        manifest_file = self.wiki_path / ".manifest.json"
        config = WikiSyncConfig(wiki_dir=self.wiki_path, manifest_path=manifest_file, dry_run=False)

        syncer = WikiSync(mock_client, config)
        first_result = syncer.sync()
        self.assertEqual(first_result.synced, 2)
        self.assertEqual(first_result.skipped, 0)
        self.assertTrue(manifest_file.exists())

        # Second sync without changes
        second_result = syncer.sync()
        self.assertEqual(second_result.synced, 0)
        self.assertEqual(second_result.skipped, 2)
        self.assertEqual(mock_client.remember.call_count, 2)  # No extra calls

    def test_sync_force_overrides_manifest(self):
        mock_client = MagicMock()
        mock_client.remember.return_value = {"id": 101, "status": "saved"}
        manifest_file = self.wiki_path / ".manifest.json"
        config = WikiSyncConfig(wiki_dir=self.wiki_path, manifest_path=manifest_file, dry_run=False)

        syncer = WikiSync(mock_client, config)
        syncer.sync()

        # Force sync
        force_result = syncer.sync(force=True)
        self.assertEqual(force_result.synced, 2)
        self.assertEqual(force_result.skipped, 0)
        self.assertEqual(mock_client.remember.call_count, 4)

    def test_sync_handles_chunking_for_large_documents(self):
        mock_client = MagicMock()
        mock_client.remember.return_value = {"id": 101, "status": "saved"}

        # Create a document with two distinct sections
        doc = "# Big Document\n\n## Section One\n" + ("Info 1 " * 50) + "\n\n## Section Two\n" + ("Info 2 " * 50)
        (self.wiki_path / "BigDoc.md").write_text(doc, encoding="utf-8")

        config = WikiSyncConfig(
            wiki_dir=self.wiki_path,
            allowlist=("BigDoc.md",),
            max_chunk_chars=200,
            dry_run=False,
        )
        syncer = WikiSync(mock_client, config)
        result = syncer.sync()

        self.assertGreater(result.synced, 1)
        sources = [c.kwargs.get("source") for c in mock_client.remember.call_args_list]
        self.assertTrue(any("BigDoc.md#section-one" in s for s in sources))
        self.assertTrue(any("BigDoc.md#section-two" in s for s in sources))

    def test_cli_dry_run_success(self):
        from mindhub.wiki_sync import main
        code = main(["--wiki-dir", str(self.wiki_path), "--dry-run"])
        self.assertEqual(code, 0)

    def test_cli_requires_api_key_when_not_dry_run(self):
        from mindhub.wiki_sync import main
        code = main(["--wiki-dir", str(self.wiki_path), "--endpoint", "http://127.0.0.1:8087/mcp", "--api-key", ""])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()

