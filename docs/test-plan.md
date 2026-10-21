# MCP Adapter Test Plan

## Status dan skop

Pelan ini hanya untuk perancangan ujian MCP adapter Hermes. Tiada implementation code atau dependency baharu ditambah melalui dokumen ini.

Ujian awal mesti menggunakan mock atau local server dan tidak boleh menyentuh gateway production, container production atau database production.

## Test boundary lokal

Gunakan satu test double/local MCP server yang:

- mendengar pada port lokal yang berasingan daripada port production,
- menyediakan tool `search_memory` dan `remember`,
- boleh mengembalikan hasil deterministik tanpa MySQL,
- boleh mensimulasikan authentication failure dan gateway failure,
- menggunakan API key sintetik yang hanya wujud dalam proses ujian,
- tidak membaca `.env` production atau data memory sebenar.

Test adapter hendaklah menunjuk kepada endpoint lokal melalui konfigurasi ujian. Endpoint sebenar, path trailing slash, handshake dan discovery perlu diuji terhadap local server dahulu sebelum sebarang pertimbangan production.

Cara menjalankan secara konseptual:

1. Mulakan local test double dengan state kosong dan data sintetik.
2. Tetapkan endpoint MCP lokal serta secret sintetik dalam environment proses ujian sahaja.
3. Jalankan test client Hermes terhadap handshake dan tool discovery.
4. Jalankan test cases di bawah.
5. Matikan local server dan pastikan tiada connection kepada host production.

Command sebenar belum ditetapkan kerana implementation dan test runner belum wujud.

## Kontrak input/output minimum

Kontrak ini datang daripada dokumentasi source, bukan hasil MCP runtime.

### `search_memory`

Input minimum:

```text
query: string, wajib dan tidak kosong selepas trim
limit: integer, optional, default 10, julat 1–50
```

Output minimum yang diketahui:

- hasil carian memory,
- field source yang dilihat: `id`, `project_id`, `memory_type`, `content`, `source`, `explicitness`, `created_at`.

Bentuk envelope MCP, bentuk senarai kosong dan metadata tool masih pending verification.

### `remember`

Input minimum:

```text
content: string, wajib, 1–60000 aksara
memory_type: string, optional, default fact, maksimum 50 aksara
source: string atau null, optional
```

Output minimum yang diketahui:

- ID memory yang disimpan,
- status simpanan.

Bentuk envelope MCP dan format error masih pending verification.

## Test cases

### Connection, handshake dan discovery

| ID | Kes | Jangkaan minimum |
|---|---|---|
| MCP-01 | Connect ke endpoint local Streamable HTTP | Client tidak connect ke production; hasil handshake direkodkan tanpa menganggap format tertentu sebelum disahkan |
| MCP-02 | Tool discovery selepas handshake | Client dapat mengenal pasti `search_memory` dan `remember`, atau ujian gagal dengan bukti response sebenar |
| MCP-03 | Endpoint path `/mcp` dan variasi trailing slash | Behavior sebenar direkodkan; tiada andaian routing dibuat |
| MCP-04 | Header authentication pada request MCP | Penghantaran header diuji menggunakan secret sintetik sahaja |

### `search_memory`

| ID | Input | Jangkaan minimum |
|---|---|---|
| SM-01 | Query sah, `limit` tidak diberi | Tool dipanggil dengan default `limit=10`; hasil source-compatible diterima |
| SM-02 | Query sah, `limit=1` dan `limit=50` | Kedua-dua boundary sah |
| SM-03 | Query dengan whitespace di sekeliling | Query di-trim berdasarkan source |
| SM-04 | Query kosong | Ditolak; bentuk error MCP sebenar pending verification |
| SM-05 | Query melebihi 200 aksara jika adapter menggunakan HTTP contract | Behavior perlu direkodkan; had ini datang daripada REST model dan belum disahkan sebagai had MCP |
| SM-06 | `limit=0` atau `limit=51` | Ditolak berdasarkan validation tool source |
| SM-07 | Query sah tetapi tiada padanan | Hasil kosong direkodkan tanpa mereka bentuk envelope baharu |
| SM-08 | Gateway/database failure disimulasi | Client mengesan kegagalan; status/error envelope sebenar pending verification |

### `remember`

| ID | Input | Jangkaan minimum |
|---|---|---|
| RM-01 | Content sah dengan default `memory_type` | Tool menerima input minimum yang didokumenkan |
| RM-02 | Content sah dengan `memory_type` dan `source` | Nilai diterima mengikut kontrak source |
| RM-03 | Content kosong atau whitespace | Ditolak |
| RM-04 | Content melebihi 60000 aksara | Ditolak |
| RM-05 | `memory_type` kosong | Behavior perlu disahkan kerana source tool dan HTTP model mempunyai validation yang berbeza |
| RM-06 | `source=null` | Diterima sebagai optional berdasarkan source |
| RM-07 | Simpanan berjaya dalam local test double | Output hanya disahkan pada tahap ID dan status minimum; envelope penuh pending verification |
| RM-08 | Gateway/database failure disimulasi | Client mengesan kegagalan; jangan anggap error envelope REST sebagai envelope MCP |

### Authentication

| ID | Kes | Jangkaan minimum |
|---|---|---|
| AUTH-01 | Header `X-API-Key` tiada | Akses ditolak; source REST middleware menunjukkan `401`, tetapi behavior MCP runtime perlu disahkan |
| AUTH-02 | API key salah | Akses ditolak; jangan log atau paparkan nilai secret |
| AUTH-03 | API key sintetik betul pada local test double | Request boleh diteruskan kepada handshake/discovery/tool call mengikut behavior local server |

## Data keselamatan ujian

- Gunakan content sintetik yang tidak mengandungi memory sebenar.
- Jangan import database dump.
- Jangan connect kepada MySQL production.
- Jangan gunakan API key production.
- Jangan simpan secret test dalam Git.
- Pastikan log ujian tidak mencetak header authentication.

## Exit criteria Fasa 2

Fasa ini dianggap lengkap apabila dokumen dan keputusan semakan manusia telah menetapkan:

- endpoint local test yang dipersetujui,
- handshake dan discovery yang diperhatikan daripada local MCP server,
- input/output minimum untuk kedua-dua tool,
- behavior authentication failure,
- behavior empty result,
- behavior gateway failure,
- sempadan jelas antara contract source dan contract runtime.

Tiada test terhadap production diperlukan untuk melengkapkan fasa perancangan ini.
