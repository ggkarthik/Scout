ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS source_finding_count bigint NOT NULL DEFAULT 0;

ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS last_rebuild_duration_ms bigint;
