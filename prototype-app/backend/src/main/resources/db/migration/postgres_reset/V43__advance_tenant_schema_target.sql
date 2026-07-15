-- migration-guard: platform-only
ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 43;

UPDATE platform.tenant_schema_versions
SET target_version = 43,
    updated_at = now()
WHERE target_version < 43;
