# mindhub

Project-centric AI Coworker memory state engine, standalone MCP Streamable HTTP server, dan MCP client adapter.

`mindhub` menyediakan platform rakan sekerja AI yang mengekalkan kesinambungan projek (**Project Continuity**) serta ingatan fakta aktif (**Active Memory**) merentas ejen seperti **Hermes Agent**, **Antigravity**, dan ejen luaran/cloud.

Ia boleh dijalankan sebagai:
1. **Pelayan MCP Mandiri (Standalone MCP Server)**: FastMCP + FastAPI berasaskan SQLite (atau MySQL) dengan sokongan auth `X-API-Key` dan endpoint `/health`.
2. **Modul Adapter / Client**: Integrasi pustaka Python standard ringan tanpa kebergantungan luar untuk berhubung dengan gateway atau pelayan MCP lain.

---

## 🎯 Ciri-ciri Utama

- **Standalone FastMCP + FastAPI Server**: Pelayan sedia-guna yang mendedahkan 5 alatan MCP penting di laluan `/mcp` menggunakan protokol *Streamable HTTP*.
- **5 Alatan MCP Bersepadu**:
  - `remember`: Simpan memori baharu (kandungan, jenis memori, sumber, project ID).
  - `search_memory`: Carian teks memori aktif & belum tamat tempoh.
  - `get_project_state`: Dapatkan snapshot keadaan semasa projek.
  - `update_project_state`: Tambah snapshot jujukan projek baharu (goal, status, progress, decisions, blockers).
  - `get_project_state_history`: Dapatkan keseluruhan sejarah snapshot mengikut turutan.
- **SQLite Persistence (Default)**: Backend thread-safe terbina dalam Python (`sqlite3`) dengan migrasi skema automatik dan mod WAL — tiada pemasangan server database luar diperlukan.
- **MySQL Persistence (Pilihan)**: Backend transaksi MySQL 8.4 dengan kawalan konkurensi selamat (`SELECT ... FOR UPDATE`) untuk persekitaran berskala besar.
- **Kawalan Keselamatan & Auth**: Middleware `X-API-Key` berasaskan pembolehubah `MINDHUB_API_KEYS` (kunci tidak sekali-kali dicatat dalam log), dan endpoint `/health` tanpa auth untuk healthcheck.
- **Standard MCP Streamable HTTP Client**: Klien ringan berasaskan Python standard library (`urllib`, `json`, `dataclasses`, `threading`) tanpa kebergantungan pihak ketiga.
- **GitHub Wiki to MCP Sync**: Penyegerakan sehala terkawal untuk memuat naik dokumentasi GitHub Wiki ke memori AI dengan sokongan allowlist, chunking, dan sanitasi rahsia.

---

## 🏗️ Seni Bina

```text
  +----------------------+  +----------------------+  +----------------------+
  | Hermes Agent         |  | Antigravity (IDE)    |  | Cloud Agents / CLI   |
  +----------------------+  +----------------------+  +----------------------+
             |                         |                         |
             +------------+            |            +------------+
                          |            |            |
                          v            v            v
           +-------------------------------------------------------+
           |               Cloudflare Tunnel / LAN                 |
           +-------------------------------------------------------+
                                       |
                                       | Streamable HTTP (X-API-Key)
                                       v
+----------------------------------------------------------------------------------+
| Standalone Mindhub Server (FastAPI + FastMCP :8088)                              |
|                                                                                  |
|  Endpoints:                                                                      |
|  - GET /health                                                                   |
|  - POST /mcp (Streamable HTTP MCP)                                               |
|                                                                                  |
|  Exposed Tools:                                                                  |
|  - remember                       - get_project_state                            |
|  - search_memory                  - update_project_state                         |
|                                   - get_project_state_history                    |
+----------------------------------------------------------------------------------+
                                       |
                     +-----------------+-----------------+
                     |                                   |
                     v (Default)                         v (Optional)
+------------------------------------------+  +------------------------------------+
| SQLite Database (mindhub.db)             |  | MySQL 8.4 Database                 |
| - memories                               |  | - memories                         |
| - project_state_snapshots                |  | - project_state_snapshots          |
| - project_state_current                  |  | - project_state_current            |
+------------------------------------------+  +------------------------------------+
```

---

## 📦 Pemasangan

### Mod Pelayan Mandiri (Standalone Server - SQLite Default)
```bash
pip install -e .
```

### Mod Penuh bersama Sokongan MySQL
```bash
pip install -e .[mysql]
```

---

## 🚀 Menjalankan Pelayan Mandiri (Standalone Server)

### 1. Tetapkan Pembolehubah Persekitaran

```bash
# Kunci API yang dibenarkan (pisahkan dengan koma untuk berbilang ejen)
export MINDHUB_API_KEYS="hermes-secret-key,antigravity-secret-key"

# (Pilihan) Lokasi fail pangkalan data SQLite (default: mindhub.db)
export MINDHUB_DB_PATH="/path/to/mindhub.db"
```

Pada Windows PowerShell:
```powershell
$env:MINDHUB_API_KEYS="hermes-secret-key,antigravity-secret-key"
$env:MINDHUB_DB_PATH="mindhub.db"
```

### 2. Mulakan Pelayan

Melalui modul:
```bash
python -m mindhub
```

Atau melalui perintah entry point:
```bash
mindhub-server
```

Pelayan akan mula beroperasi pada `http://0.0.0.0:8088`.
- Endpoint kesihatan: `http://127.0.0.1:8088/health`
- Endpoint MCP: `http://127.0.0.1:8088/mcp` (memerlukan header `X-API-Key`)

---

## 💡 Konfigurasi Client MCP (Contoh)

### Antigravity (`mcp_config.json`)
```json
{
  "mcpServers": {
    "mindhub": {
      "url": "http://127.0.0.1:8088/mcp",
      "headers": {
        "X-API-Key": "antigravity-secret-key"
      }
    }
  }
}
```

### Hermes Agent (`config.yaml`)
```yaml
mcp_servers:
  mindhub:
    url: "http://127.0.0.1:8088/mcp"
    headers:
      X-API-Key: "herme...key"
```

> Ini ialah contoh konfigurasi sasaran. Setakat verifikasi **2026-10-24**, konfigurasi Hermes aktif masih menunjuk `ai-memory` pada `127.0.0.1:8087`; ia belum wired ke Mindhub `:8088`.

---

## ✅ Status Verifikasi Integrasi

Verifikasi read-only pada **2026-10-24** mengesahkan `mindhub.service` aktif di `node01:8088`, `/health` HTTP 200, auth diperlukan, Streamable HTTP `initialize` berjaya dengan session, tepat 5 tools tersedia, dan `get_project_state(1)` mengembalikan sequence 1. Ujian repo: `123 passed, 3 skipped`.

Butiran kontrak source, boundary legacy, konfigurasi Hermes yang belum wired, dan had adapter ada di [MCP Integration Contract](docs/mcp-integration.md).

---

## 🐍 Penggunaan Pustaka Python (Client & Utility)

### 1. Client MCP (Hermes Agent / Skrip Luar)

```python
from mindhub import StreamableHTTPMCPClient

client = StreamableHTTPMCPClient(
    "http://127.0.0.1:8088/mcp",
    api_key="hermes-secret-key",
)

# Handshake & discover tools
client.initialize()
tools = client.list_tools()

# Kemas kini status projek
snapshot = client.update_project_state(
    project_id=1,
    state={
        "current_goal": "Integrasi Hermes dengan Standalone Mindhub",
        "status": "in_progress",
        "progress": "Pelayan SQLite beroperasi, menyegerak snapshot projek",
        "decisions": ["Gunakan Standalone SQLite Mindhub"],
        "blockers": [],
        "next_action": "Sambungkan cloud agents",
    },
)

# Dapatkan status semasa
current = client.get_project_state(project_id=1)
print(f"Goal semasa (Seq {current['sequence']}): {current['current_goal']}")
```

### 2. GitHub Wiki to MCP Memory Sync

Muat naik dokumentasi Wiki ke memori Mindhub:

```bash
# Simulasi (dry-run)
python -m mindhub.wiki_sync --wiki-dir ./wiki --dry-run

# Segerakkan dengan allowlist halaman terpilih
python -m mindhub.wiki_sync \
  --wiki-dir ./wiki \
  --allowlist "Home.md,Architecture.md" \
  --api-key "$MINDHUB_API_KEY"
```

Lihat maklumat lanjut dalam [docs/wiki-sync.md](docs/wiki-sync.md).

---

## 🧪 Ujian (Testing)

Semua unit tests (termasuk SQLite in-memory, mock HTTP transport, dan logik memori) boleh dijalankan tanpa sebarang database luar:

```bash
python -m unittest discover tests
```

---

## 📚 Dokumentasi Lanjut

- [Architecture & Boundaries](docs/architecture.md)
- [HTTP API Contract](docs/api-contract.md)
- [MCP Tools Documentation](docs/mcp-tools.md)
- [Database Schema](docs/database-schema.md)
- [MCP Integration Contract](docs/mcp-integration.md)
- [Test Plan](docs/test-plan.md)
- [Offline ai-memory JSONL Import](docs/migration-import.md)
- [OAuth 2.1 Facade (Claude & Gemini Connectors)](docs/oauth-facade.md)

---

## 🔐 OAuth 2.1 Facade (Claude & Gemini Connectors)

Mindhub includes an OAuth 2.1 facade (`mindhub_oauth`) enabling external AI clients (Claude web/mobile, Google Gemini) to connect securely to Mindhub's MCP server via RFC 6749, RFC 7636 (mandatory PKCE S256), RFC 8707 (Resource Indicators), and Dynamic Client Registration (RFC 7591). The facade translates external Bearer tokens into internal `X-API-Key` authentication. Existing tools (Hermes Agent, Antigravity) continue connecting directly to Mindhub untouched.

See [docs/oauth-facade.md](docs/oauth-facade.md) for architecture, configuration, endpoints, and deployment details.

---

## 🔒 Had & Keselamatan

- **Tiada rahsia dalam Git**: Fail `.env`, API key, dan pangkalan data SQLite (`*.db`) diabaikan oleh `.gitignore`.
- **Pengasingan Homelab**: Pelayan mandiri tidak mengganggu perkhidmatan legacy sedia ada pada port 8087 tanpa arahan pengguna.
