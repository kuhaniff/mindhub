# Offline ai-memory JSONL import

`mindhub.migration_import` imports an already-created, offline JSONL export into a **new** SQLite staging database. It is intentionally file-only: it does not read `.env` or `MINDHUB_DB_PATH`, connect to MySQL, call Mindhub, restart services, or perform cutover.

## Export format

Every line must be a JSON object containing these fields; blank lines are invalid:

`id`, `project_id`, `memory_type`, `content`, `source`, `explicitness`, `status`, `expires_at`, `created_at`, and `updated_at`. The source-only fields `confidence`, `verified_at`, and `superseded_by` are optional.

The importer validates required values and types, preserves all fields exactly as SQLite values, and rejects duplicate IDs. `project_id`, `source`, and `expires_at` may be `null`; `id` and `superseded_by` must be positive SQLite signed 64-bit integers, while `project_id` must be a SQLite signed 64-bit integer or `null`. Timestamps are retained as non-empty strings from the export. Optional source-only metadata is stored in `memory_source_metadata` keyed by `memory_id`; it never changes the runtime `memories` schema. Missing optional values are stored as `null`.

## Command line

Run against an offline export and a path that does not already exist:

```bash
.venv/bin/python -m mindhub.migration_import \
  /path/to/ai-memory-export.jsonl \
  /path/to/new/mindhub-staging.db
```

The destination directory must already exist. The importer builds the database in a unique temporary file in that directory, validates and commits it, then publishes it with an atomic no-overwrite operation. Existing destinations and destination sidecars are rejected and preserved; temporary staging files are removed if validation, insertion, or publication fails. A successful run prints the imported row count.

Inspect the staging database independently before any later migration decision:

```bash
sqlite3 /path/to/new/mindhub-staging.db \
  'SELECT id, project_id, memory_type, content, source, explicitness, status, expires_at, created_at, updated_at FROM memories ORDER BY id;'
```
