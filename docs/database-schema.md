# Database Schema

## Status

Schema sebenar database belum disahkan. Tiada SQL DDL, migration atau schema file ditemui dalam source yang diaudit. Database dan container production tidak diakses.

Maklumat di bawah hanyalah kolum dan behavior yang dirujuk oleh application source.

## Table yang dirujuk

```text
memories
```

## Kolum yang dirujuk

| Kolum | Cara digunakan oleh source |
|---|---|
| `id` | Dipulangkan dalam hasil carian dan ID memory baharu |
| `project_id` | Disimpan dan dipulangkan |
| `memory_type` | Disimpan dan dipulangkan |
| `content` | Disimpan dan digunakan untuk carian `LIKE` |
| `source` | Disimpan dan dipulangkan |
| `explicitness` | Disimpan dan dipulangkan |
| `status` | Ditapis kepada nilai `active` ketika carian |
| `expires_at` | Row dikecualikan jika tarikh telah luput |
| `created_at` | Dipulangkan dalam hasil carian |
| `updated_at` | Digunakan untuk susunan menurun |

## Query behavior yang disahkan

Carian memilih kolum berikut:

```text
id, project_id, memory_type, content,
source, explicitness, created_at
```

Dengan syarat:

```text
status = 'active'
AND (expires_at IS NULL OR expires_at > NOW())
AND content LIKE <query>
```

Insert menggunakan kolum:

```text
project_id, memory_type, content, source, explicitness
```

## Belum diketahui

Perkara berikut tidak dapat ditentukan daripada application source sahaja:

- Jenis data setiap kolum.
- Primary key dan auto-increment behavior.
- Default value database.
- Index dan query optimization.
- Foreign key kepada table lain.
- Constraint `status`, `memory_type` atau `explicitness`.
- Timezone dan precision timestamp.
- Migration history.
- Data retention dan cleanup process.

Jangan bina migration atau model database production berdasarkan dokumen ini tanpa pengesahan schema rasmi.
