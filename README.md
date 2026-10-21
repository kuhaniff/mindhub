# mindhub

Project-centric AI Coworker memory state engine dan MCP Streamable HTTP adapter.

`mindhub` direka khusus untuk memperluaskan fungsi **AI Memory Gateway** pada `node01` (Debian 13, Intel Core i3, 7.6GB RAM) supaya bertukar daripada simpanan fakta pasif (`remember` / `search_memory`) kepada platform rakan sekerja AI yang mengekalkan kesinambungan projek (**Project Continuity**).

---

## 🎯 Ciri-ciri Utama

- **Project State Engine**: Menyimpan snapshot keadaan projek yang tidak boleh diubah (*immutable snapshots*) dengan nombor jujukan monotonik (`sequence`) dan pointer keadaan semasa (`project_state_current`).
- **Standard MCP Streamable HTTP Client**: Client ringan berasaskan Python standard library (`urllib`, `json`, `dataclasses`, `threading`) tanpa kebergantungan luar. Menyokong JSON-RPC 2.0 dan *Server-Sent Events* (`text/event-stream`).
- **FastMCP Tool Registrar**: Membolehkan server gateway mendaftar tool `get_project_state`, `update_project_state`, dan `get_project_state_history` secara bersih tanpa *side effects* semasa import.
- **Transactional MySQL Persistence**: Backend MySQL 8.4 dengan kawalan konkurensi selamat (`SELECT ... FOR UPDATE`), pengurusan zon masa UTC, dan pengasingan credential runtime.
- **Idempotent Migration Runner**: Utiliti migrasi automatik untuk melancarkan skema `sql/project_state.sql` ke database sasaran secara selamat.
- **Privasi & Keselamatan Tinggi**: Pemadanan dan penapisan automatik (`[REDACTED]`) bagi API Key dalam mesej ralat MCP.

---

## 🏗️ Seni Bina

```text
                  +-----------------------------------+
                  |     Hermes Agent (Node01)         |
                  +-----------------------------------+
                                    |
                                    | Streamable HTTP (MCP)
                                    v
+-------------------------------------------------------------------------+
| AI Memory Gateway (FastAPI / FastMCP)                                   |
|                                                                         |
|  Legacy Tools:            Project State Tools:                          |
|  - search_memory          - get_project_state                           |
|  - remember               - update_project_state                        |
|                           - get_project_state_history                   |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| MySQL 8.4 (Named volume / apps-network)                                 |
|                                                                         |
|  - memories (raw memories)                                              |
|  - project_state_snapshots (immutable sequence history)                 |
|  - project_state_current (active snapshot pointer)                      |
+-------------------------------------------------------------------------+
```

---

## 📦 Pemasangan

### Mod Asas (Client sahaja - tiada dependency luar)
```bash
pip install -e .
```

### Mod Penuh (Bersama MySQL persistence)
```bash
pip install -e .[mysql]
```

---

## 🚀 Penggunaan Pantas

### 1. Client MCP (Hermes Agent / Klien Luar)

```python
from mindhub import StreamableHTTPMCPClient

client = StreamableHTTPMCPClient(
    "http://127.0.0.1:8087/mcp",
    api_key="your-runtime-api-key",
)

# Handshake & discover tools
client.initialize()
tools = client.list_tools()

# Kemas kini status projek
snapshot = client.update_project_state(
    project_id=1,
    state={
        "current_goal": "Integrasi Hermes dengan AI Memory",
        "status": "in_progress",
        "progress": "Ujian handshake lulus, menambah project state",
        "decisions": ["Gunakan existing gateway", "Tolak Mnemosyne"],
        "blockers": [],
        "next_action": "Jalankan migrasi database di node01",
    },
)

# Dapatkan status semasa
current = client.get_project_state(project_id=1)
print(f"Goal semasa (Seq {current['sequence']}): {current['current_goal']}")
```

### 2. Mendaftarkan Tools pada Gateway (FastMCP / FastAPI)

```python
from mcp.server.fastmcp import FastMCP
from mindhub.gateway_project_state import register_project_state_tools
from mindhub.mysql_project_state import MySQLProjectStatePersistence

mcp = FastMCP("ai-memory")
persistence = MySQLProjectStatePersistence.from_env()

# Daftar ketiga-tiga project state tools
register_project_state_tools(mcp, persistence)
```

### 3. Menjalankan Migrasi Database

```python
from mindhub.migrations import apply_migrations
import mysql.connector

conn = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,
    user="ai_memory_user",
    password="...",
    database="ai_memory",
)
apply_migrations(conn)
conn.close()
```

Atau melalui baris arahan (menggunakan pembolehubah persekitaran `MYSQL_*`):
```bash
python -m mindhub.migrations
```

---

## 🧪 Ujian (Testing)

Semua unit tests, mock HTTP transport tests, dan concurrency tests boleh dijalankan tanpa sebarang database luaran:

```bash
python -m unittest discover tests
```

### Ujian Integrasi MySQL (Disposable)
Untuk mengelakkan sebarang gangguan terhadap data sebenar, ujian integrasi MySQL dilindungi oleh pagar keselamatan (*safety guardrail*):

```bash
set MINDHUB_TEST_MYSQL_DISPOSABLE=1
set MINDHUB_TEST_MYSQL_DATABASE=mindhub_test
set MINDHUB_TEST_MYSQL_HOST=127.0.0.1
set MINDHUB_TEST_MYSQL_PORT=33307
set MINDHUB_TEST_MYSQL_USER=test_user
set MINDHUB_TEST_MYSQL_PASSWORD=test_pass

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

---

## 🔒 Had & Keselamatan

- **Tiada rahsia dalam Git**: Fail `.env`, API key, dan password database tidak sekali-kali disimpan di dalam kod sumber.
- **Pengasingan Homelab**: Ujian automatik tidak akan menyambung ke host pengeluaran `node01` secara lalai.
