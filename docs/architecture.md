# Architecture

## Status maklumat

Dokumen ini berdasarkan audit read-only terhadap source yang ditemui di `/home/aneep/stacks/ai-memory`. Ia menerangkan struktur source yang diaudit, bukan pengesahan keadaan runtime production.

## Komponen yang disahkan melalui source

```text
Client
  |
  | HTTP
  v
FastAPI application
  |-- GET /health
  |-- GET /memories
  |-- POST /memories
  `-- /mcp (streamable HTTP MCP application)
          |
          v
      MCP server: ai-memory
          |
          v
      MySQL melalui mysql-connector-python
```

Komponen runtime yang dikenal pasti:

- Python base image: `python:3.13-slim`
- FastAPI + Uvicorn
- `mysql-connector-python`
- `mcp>=2.1.0`
- Docker Compose service bernama `ai-memory`
- Docker container name: `ai-memory`
- Container port: `8000`
- Host binding dalam compose: `127.0.0.1:8087:8000`
- External Docker network: `apps-network`

Compose yang diaudit hanya mengandungi gateway. Ia tidak mentakrifkan service MySQL.

## Authentication yang disahkan melalui source

Middleware HTTP memerlukan header `X-API-Key` untuk path berikut:

- `/memories`
- `/memories/...`
- `/mcp`
- `/mcp/...`

`/health` tidak termasuk dalam senarai path protected yang dilihat dalam source.

Nilai API key tidak didokumentasikan di sini. Ia dibaca daripada environment runtime dan tidak diaudit.

## Belum disahkan

Perkara berikut belum disahkan secara live dan tidak boleh dianggap sebagai fakta deployment:

- Sama ada container sedang berjalan.
- Sama ada port host `8087` sedang listen.
- Keadaan atau versi database MySQL.
- Schema sebenar, index dan migration database.
- Nilai environment runtime.
- Status network `apps-network`.
- Laluan deployment sebenar pada `node01`.
- Sifat source backup `main.py.before-*` terhadap implementation semasa.
