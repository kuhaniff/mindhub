# MCP Tools

Source semasa mendedahkan lima tool pada endpoint `/mcp` menggunakan Streamable HTTP:

- `search_memory`
- `remember`
- `get_project_state`
- `update_project_state`
- `get_project_state_history`

Dokumen ini menerangkan kontrak source untuk tool memory. Status runtime dan batas integrasi ada dalam [MCP Integration Contract](mcp-integration.md).

## `search_memory`

Tujuan: mencari memory aktif berdasarkan perkataan dalam kandungan.

Input:

| Nama | Jenis | Default | Syarat |
|---|---|---|---|
| `query` | string | — | tidak boleh kosong selepas trim |
| `limit` | integer | `10` | `1` hingga `50` |

Behavior yang disahkan daripada source:

- Query di-trim.
- Carian menggunakan padanan `LIKE` terhadap `memories.content`.
- Hanya row dengan `status = 'active'` dipilih.
- Row yang telah luput dikecualikan jika `expires_at` bukan `NULL`.
- Keputusan disusun berdasarkan `updated_at DESC`.

## `remember`

Tujuan: menyimpan satu memory baharu.

Input:

| Nama | Jenis | Default | Syarat |
|---|---|---|---|
| `content` | string | — | tidak boleh kosong, maksimum 60000 aksara |
| `memory_type` | string | `fact` | di-trim dan dipotong kepada maksimum 50 aksara oleh source |
| `source` | string atau null | `null` | optional |
| `project_id` | integer atau null | `null` | optional |

Respons source berbentuk objek yang mengandungi rekod memory yang disimpan; ID dijana oleh database.

## Project state tools

- `get_project_state(project_id)` mendapatkan snapshot semasa untuk project.
- `update_project_state(project_id, state)` mencipta snapshot baharu.
- `get_project_state_history(project_id)` mendapatkan sejarah snapshot mengikut turutan.

## Transport dan keselamatan

- MCP menggunakan Streamable HTTP pada `/mcp`.
- Endpoint `/health` dikecualikan daripada auth.
- Path lain memerlukan `X-API-Key`, dengan key dibaca daripada `MINDHUB_API_KEYS`.
- Nilai API key tidak disimpan dalam dokumentasi ini.

Butiran session live, konfigurasi Hermes yang belum wired, dan had adapter didokumenkan dalam [MCP Integration Contract](mcp-integration.md).
