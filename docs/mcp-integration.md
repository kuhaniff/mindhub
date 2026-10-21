# MCP Integration Contract

## Status

Ini ialah perancangan integrasi untuk Hermes berdasarkan dokumentasi source audit. Ia belum diuji dengan MCP client sebenar dan belum menjadi implementation contract yang muktamad.

## Fakta yang disahkan melalui source audit

- MCP server dinamakan `ai-memory`.
- MCP application di-mount pada path `/mcp`.
- Transport dinyatakan sebagai Streamable HTTP.
- `json_response=True` dan `stateless_http=True` dinyatakan dalam source.
- Middleware HTTP melindungi `/mcp` dan subpath `/mcp/...` dengan header `X-API-Key`.
- Compose yang diaudit memetakan host `127.0.0.1:8087` kepada port container `8000`.
- Tool yang dideklarasikan ialah `search_memory` dan `remember`.

## Cara Hermes dijangka connect

Urutan konseptual yang dicadangkan:

1. Hermes menggunakan MCP client yang menyokong Streamable HTTP.
2. Client dikonfigurasi dengan endpoint gateway pada URL yang mengandungi `/mcp`.
3. Client menghantar `X-API-Key` melalui konfigurasi secret yang tidak disimpan dalam repo.
4. Client melakukan handshake MCP.
5. Client meminta tool discovery.
6. Hermes mengesahkan kewujudan `search_memory` dan `remember` sebelum memanggilnya.
7. Hermes memanggil tool menggunakan input minimum yang didokumenkan.

Urutan ini ialah **andaian integrasi** sehingga diuji dengan client dan server sebenar.

## Perkara yang mesti disahkan

### Endpoint dan routing

- URL sebenar yang perlu digunakan oleh Hermes.
- Sama ada endpoint tepat ialah `/mcp`, `/mcp/` atau path lain hasil routing transport.
- Sama ada `127.0.0.1:8087` hanya sesuai untuk client pada mesin yang sama.
- Routing jika Hermes dan gateway berjalan pada host berbeza.

### Streamable HTTP

- Format request pertama yang dijangka oleh server.
- Format handshake dan response.
- Keperluan header `Accept`, `Content-Type` atau header MCP lain.
- Sokongan connection/session behavior walaupun source menetapkan stateless HTTP.
- Cara client mengendalikan response JSON dan error daripada transport.

### Authentication

- Header `X-API-Key` disahkan pada handshake, setiap request, atau kedua-duanya.
- Behavior jika header tiada atau nilainya salah.
- Cara Hermes menyimpan dan menyuntik secret tanpa memasukkannya ke source, log atau Git.
- Sama ada authentication middleware menghasilkan HTTP `401` yang sama untuk semua request MCP.

### Handshake dan tool discovery

- Protocol version yang digunakan ketika runtime.
- Nama method handshake dan discovery yang sebenar.
- Schema input yang dihantar oleh server kepada client.
- Metadata, description dan annotations tool.
- Format response discovery.
- Format error apabila tool tidak wujud atau input tidak sah.

Semua perkara di atas kekal **pending verification**. Jangan reka response atau error envelope sebelum ujian sebenar.

## Kontrak minimum berdasarkan dokumentasi sedia ada

### `search_memory`

Input minimum:

| Field | Jenis | Syarat |
|---|---|---|
| `query` | string | tidak kosong selepas trim |
| `limit` | integer | optional, default `10`, julat `1` hingga `50` |

Behavior source yang diketahui: carian dibuat pada memory aktif, memory yang belum luput, dan disusun mengikut `updated_at DESC`.

Output minimum yang didokumenkan: senarai row memory. Field yang kelihatan dalam hasil source ialah `id`, `project_id`, `memory_type`, `content`, `source`, `explicitness` dan `created_at`.

Bentuk envelope MCP dan bentuk khusus hasil kosong **belum disahkan**.

### `remember`

Input minimum:

| Field | Jenis | Syarat |
|---|---|---|
| `content` | string | tidak kosong, maksimum 60000 aksara |
| `memory_type` | string | optional, default `fact`, maksimum 50 aksara |
| `source` | string atau null | optional |

Output minimum yang kelihatan dalam source ialah hasil yang mengandungi ID memory dan status simpanan. Nilai sebenar ID dijana database.

Bentuk envelope MCP dan error response **belum disahkan**.

## Boundary integrasi

MCP adapter Hermes tidak boleh:

- membaca `.env` secara terus ke dalam repo,
- menyalin API key ke konfigurasi tracked,
- menganggap URL deployment sudah diketahui,
- menggunakan database production untuk ujian awal,
- menganggap HTTP API REST dan MCP mempunyai error envelope yang sama.
