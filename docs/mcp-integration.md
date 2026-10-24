# MCP Integration Contract

## Status ringkas

Dokumen ini membezakan empat perkara: kontrak semasa yang kelihatan dalam source repo, verifikasi live bertarikh **2026-10-24**, konfigurasi Hermes yang **belum disambungkan** ke Mindhub, dan had adapter yang masih diketahui. Ia tidak mendakwa bahawa konfigurasi Hermes atau adapter telah dipatch.

## Kontrak semasa berdasarkan source repo

- Pelayan dinamakan `mindhub` dan disediakan sebagai standalone FastAPI + MCP server.
- MCP dihidangkan pada path `/mcp` menggunakan **Streamable HTTP**.
- Default entry point menjalankan server pada `0.0.0.0:8088`; `/health` disediakan tanpa auth.
- Semua path selain `/health` memerlukan header `X-API-Key`, dengan nilai dibaca daripada `MINDHUB_API_KEYS`.
- Lima tool yang didaftarkan ialah:
  - `search_memory`
  - `remember`
  - `get_project_state`
  - `update_project_state`
  - `get_project_state_history`
- `get_project_state`, `update_project_state`, dan `get_project_state_history` menggunakan `project_id`; operasi update menerima objek `state`.
- Adapter client menggunakan header `X-API-Key`, menjalankan MCP `initialize`, menyimpan `MCP-Session-ID` apabila diterima, dan menyokong response JSON serta data frame JSON yang biasa dalam SSE.

Kontrak source di atas menerangkan apa yang repo semasa tetapkan; ia bukan bukti bahawa instance live atau konfigurasi client tertentu telah menggunakannya.

## Verifikasi live — 2026-10-24

Verifikasi read-only terhadap `node01` mengesahkan perkara berikut:

- `mindhub.service` aktif dan mendengar pada `0.0.0.0:8088`.
- `GET /health` mengembalikan HTTP `200`.
- Request MCP tanpa auth ditolak dengan HTTP `401`.
- `initialize` yang diautentikasi mengembalikan HTTP `200` dan session ID.
- Tool surface live tepat lima tool: `search_memory`, `remember`, `get_project_state`, `update_project_state`, dan `get_project_state_history`.
- Panggilan diautentikasi `get_project_state(1)` mengembalikan `sequence = 1`.
- Ujian repo yang dijalankan semasa verifikasi: `123 passed, 3 skipped`.

Verifikasi ini mengesahkan service, auth, transport, tool discovery, dan satu bacaan project state. Ia tidak mengesahkan deployment provenance, persistence selepas restart, atau laluan end-to-end melalui konfigurasi Hermes.

## Konfigurasi Hermes: belum wired

Konfigurasi Hermes semasa masih mengarahkan server legacy **`ai-memory`** pada `127.0.0.1:8087`; ia belum ditukar kepada Mindhub pada port `8088`. Maka, contoh endpoint berikut ialah bentuk sasaran sahaja dan bukan dakwaan konfigurasi aktif:

```yaml
mcp_servers:
  mindhub:
    url: "http://127.0.0.1:8088/mcp"
    headers:
      X-API-Key: "<secret-dari-secret-store>"
```

Jangan commit API key sebenar atau menyalin secret ke dokumentasi, log, atau konfigurasi tracked.

## Had adapter yang diketahui

`mindhub/mcp_adapter.py` masih mempunyai gap berikut berdasarkan semakan verifikasi:

- Tiada pemulihan session apabila request menerima HTTP `404`.
- Tiada penghantaran `DELETE` untuk menutup session.
- `structuredContent` tidak digunakan ketika mengekstrak hasil tool.
- `isError` tidak dipromosikan sebagai keadaan error adapter.

Had ini tidak mengubah fakta bahawa initialize dan tool calls asas telah diverifikasi live. Sebarang pembetulan adapter memerlukan perubahan kod dan ujian berasingan.

## Boundary sejarah

Dokumentasi audit lama merujuk service bernama `ai-memory`, host `127.0.0.1:8087`, mod stateless HTTP, dan dua tool (`search_memory` serta `remember`). Itu ialah konteks legacy yang menerangkan asal konfigurasi lama; ia **bukan** fakta semasa tentang standalone Mindhub yang diverifikasi di `:8088`.

Boundary integrasi yang kekal:

- Jangan membaca `.env` terus ke repo atau menyalin API key ke konfigurasi tracked.
- Jangan anggap URL deployment atau routing antara host sudah diketahui tanpa verifikasi.
- Jangan gunakan database production untuk ujian awal.
- Jangan anggap error envelope HTTP biasa dan MCP adalah sama.
