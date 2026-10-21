-- Standalone local migration for MySQL Project State persistence.
-- This file is not wired to production deployment or a migration runner.

CREATE TABLE IF NOT EXISTS project_state_snapshots (
    snapshot_id CHAR(36) NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    sequence BIGINT UNSIGNED NOT NULL,
    current_goal TEXT NOT NULL,
    status VARCHAR(100) NOT NULL,
    progress TEXT NOT NULL,
    decisions JSON NOT NULL,
    blockers JSON NOT NULL,
    next_action TEXT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (snapshot_id),
    UNIQUE KEY uq_project_state_sequence (project_id, sequence),
    KEY idx_project_state_project_sequence (project_id, sequence)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS project_state_current (
    project_id BIGINT UNSIGNED NOT NULL,
    last_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
    current_snapshot_id CHAR(36) NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (project_id),
    CONSTRAINT fk_project_state_current_snapshot
        FOREIGN KEY (current_snapshot_id)
        REFERENCES project_state_snapshots (snapshot_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
