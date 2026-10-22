-- Standalone local migration for MySQL Memory persistence.

CREATE TABLE IF NOT EXISTS memories (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED,
    memory_type VARCHAR(50) NOT NULL DEFAULT 'fact',
    content TEXT NOT NULL,
    source VARCHAR(255),
    explicitness VARCHAR(50) NOT NULL DEFAULT 'explicit',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    expires_at DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_memories_status_updated (status, updated_at),
    KEY idx_memories_project (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
