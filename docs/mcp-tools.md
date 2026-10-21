# MCP Tools

Source audit mengenal pasti MCP server bernama `ai-memory` yang di-mount pada `/mcp` menggunakan streamable HTTP.

Dokumen ini menerangkan deklarasi tools yang kelihatan dalam source. Ia belum disahkan melalui MCP client atau service runtime.

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

Respons source berbentuk:

```json
{
  "id": "database-generated value",
  "status": "saved"
}
```

## Transport dan keselamatan

- MCP menggunakan streamable HTTP.
- JSON response dan stateless HTTP dinyatakan dalam source.
- Path `/mcp` dilindungi oleh middleware `X-API-Key`.
- Nilai API key tidak disimpan dalam dokumentasi ini.

## Belum disahkan

- MCP protocol version yang digunakan ketika runtime.
- Tool metadata yang dihantar kepada client sebenar.
- Error envelope sebenar daripada transport.
- Authorization behavior selain middleware yang kelihatan dalam source.
