# mindhub

Dokumentasi dan perancangan awal untuk AI Memory Gateway.

## Status

Repo ini masih berada dalam fasa dokumentasi dan perancangan. Tiada source code production disalin dan tiada deployment dibuat.

## Rujukan audit

Audit read-only terhadap path yang direkodkan `/home/aneep/stacks/ai-memory` mengesahkan perkara berikut:

- Gateway menggunakan FastAPI dan Uvicorn.
- Gateway menggunakan `mysql-connector-python` untuk akses MySQL.
- Gateway mendaftarkan MCP server bernama `ai-memory`.
- HTTP API yang dikenal pasti ialah `/health` dan `/memories`.
- MCP di-mount pada `/mcp` menggunakan streamable HTTP.
- Compose mendedahkan gateway pada `127.0.0.1:8087` dan port dalaman `8000`.

Maklumat production yang tidak boleh disahkan melalui source sahaja, termasuk schema database sebenar, keadaan service semasa, nilai konfigurasi runtime dan status deployment, kekal ditandakan sebagai belum disahkan dalam dokumentasi.

## Dokumen

- [Architecture](docs/architecture.md)
- [HTTP API contract](docs/api-contract.md)
- [MCP tools](docs/mcp-tools.md)
- [Database schema](docs/database-schema.md)

## Had skop

Repo ini belum mempunyai implementation code, database migration, remote Git, commit atau push. Sebarang kerja terhadap `node01`, container, database atau gateway production memerlukan semakan dan arahan berasingan.
