# HTTP API Contract

Kontrak ini disusun daripada route dan model yang kelihatan dalam source yang diaudit. Ia belum diuji terhadap service runtime.

## Authentication

Path `/memories` memerlukan header:

```text
X-API-Key: <runtime value not documented here>
```

Nilai sebenar tidak disimpan dalam repo ini.

## `GET /health`

Route yang disahkan:

```text
GET /health
```

Respons source:

```json
{
  "status": "ok",
  "service": "ai-memory"
}
```

## `GET /memories`

Query parameters:

| Parameter | Jenis | Syarat | Default |
|---|---|---|---|
| `q` | string | 1–200 aksara | wajib |
| `limit` | integer | 1–50 | `10` |

Bentuk respons source:

```json
{
  "items": [
    {
      "id": "database value",
      "project_id": "database value",
      "memory_type": "database value",
      "content": "database value",
      "source": "database value",
      "explicitness": "database value",
      "created_at": "database value"
    }
  ]
}
```

Item sebenar bergantung pada row database. Tiada contoh data sebenar dimasukkan.

## `POST /memories`

Request body menggunakan model berikut:

```json
{
  "content": "string",
  "memory_type": "fact",
  "project_id": null,
  "source": null,
  "explicitness": "explicit"
}
```

Syarat field yang disahkan:

- `content`: wajib, 1–60000 aksara.
- `memory_type`: default `fact`, 1–50 aksara.
- `project_id`: optional, integer lebih besar daripada `0` jika diberi.
- `source`: optional, maksimum 255 aksara.
- `explicitness`: `explicit` atau `inferred`, default `explicit`.

Respons berjaya daripada source berbentuk:

```json
{
  "id": "database-generated value",
  "status": "saved"
}
```

## Error yang kelihatan dalam source

- Request tidak sah akan dikendalikan oleh validation FastAPI.
- Kegagalan sambungan MySQL dipetakan kepada HTTP `503` dengan detail `Memory database unavailable`.
- Request protected tanpa API key yang sah dipetakan kepada HTTP `401` dengan detail `Unauthorized`.

Status code lain dan format error lengkap belum disahkan melalui ujian runtime.

## Belum disahkan

- URL deployment sebenar.
- Semantik pagination selain `limit`.
- CORS, rate limiting dan observability.
- Versioning API.
- Kontrak response berdasarkan database sebenar.
