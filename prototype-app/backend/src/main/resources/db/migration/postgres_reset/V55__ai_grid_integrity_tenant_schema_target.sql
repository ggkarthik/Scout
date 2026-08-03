-- migration-guard: platform-only
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 51;
UPDATE platform.tenant_schema_versions
SET target_version = 51,
    status = CASE WHEN current_version < 51 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 51;

