# GitHub Wiki to MCP Memory Sync

`mindhub.wiki_sync` ialah alat penyegerakan sehala (*one-way sync*) terkawal untuk memuat naik dokumen GitHub Wiki (format Markdown) ke dalam memori AI Memory Gateway melalui tool MCP `remember`.

---

## 🎯 Ciri-ciri Utama

1. **Penyegerakan Sehala Terkawal**: Membaca repositori GitHub Wiki tempatan (folder fail `.md`) dan menyimpannya sebagai rekod memori jenis `wiki`.
2. **Penapisan Fleksibel (Allowlist & Denylist)**:
   - Denylist lalai: Mengecualikan fail navigasi khas GitHub Wiki seperti `_Sidebar.md`, `_Footer.md`, direktori `.git/`, dan fail bukan `.md`.
   - Allowlist pilihan: Menyokong corak glob (contoh: `Home.md`, `architecture/*`, `services/*`).
3. **Pembahagian Bahagian (Coherent Chunking)**:
   - Dokumen pendek dimuat naik sebagai satu rekod dengan metadata tajuk dan laluan fail.
   - Dokumen panjang dibahagikan mengikut tajuk bahagian Markdown (`## Heading`) dengan anchor URI (`wiki:filename.md#section-anchor`) supaya mudah dirujuk oleh LLM.
4. **Idempotensi Berasaskan Manifest (`.wiki_sync_manifest.json`)**:
   - Menyimpan hash SHA-256 bagi setiap bahagian yang telah dimuat naik.
   - Mengelakkan duplikasi rekod pada larian seterusnya sekiranya fail tidak berubah.
   - Menyokong bendera `--force` untuk memaksa penyegerakan semula.
5. **Perlindungan Rahsia (Secret Redaction)**:
   - Menapis secara automatik token dan kata laluan sensitif (seperti GitHub PAT `ghp_...`, Bearer tokens, atau penetapan `api_key = "..."`) kepada `[REDACTED_SECRET]` sebelum disimpan ke database memori.
6. **Mod Simulasi (Dry Run)**:
   - Membolehkan audit dan semakan senarai dokumen serta bahagian yang akan dimuat naik sebelum sebarang panggilan sebenar ke gateway dibuat.

---

## 🚀 Penggunaan CLI

### 1. Simulasi (Dry-Run)
Audit fail tanpa mengubah memori:
```bash
python -m mindhub.wiki_sync --wiki-dir /path/to/wiki --dry-run
```

### 2. Menggunakan Allowlist
Hanya segerakkan halaman terpilih:
```bash
python -m mindhub.wiki_sync \
  --wiki-dir /path/to/wiki \
  --allowlist "Home.md,Architecture.md,Runbooks.md" \
  --endpoint "http://127.0.0.1:8087/mcp" \
  --api-key "$MINDHUB_API_KEY"
```

### 3. Memaksa Segerak Semula (Force Re-sync)
```bash
python -m mindhub.wiki_sync \
  --wiki-dir /path/to/wiki \
  --force \
  --api-key "$MINDHUB_API_KEY"
```

---

## 🐍 Penggunaan Programmatik

```python
from pathlib import Path
from mindhub import StreamableHTTPMCPClient, WikiSync, WikiSyncConfig

client = StreamableHTTPMCPClient("http://127.0.0.1:8087/mcp", api_key="secret-key")
client.initialize()

config = WikiSyncConfig(
    wiki_dir=Path("./wiki"),
    allowlist=("Home.md", "services/*.md"),
    max_chunk_chars=4000,
    dry_run=False,
)

syncer = WikiSync(client, config)
result = syncer.sync()

print(f"Scanned: {result.scanned}, Synced: {result.synced}, Skipped: {result.skipped}")
```
