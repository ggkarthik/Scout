-- migration-guard: platform-only
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 50;
UPDATE platform.tenant_schema_versions
SET target_version = 50,
    status = CASE WHEN current_version < 50 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 50;
