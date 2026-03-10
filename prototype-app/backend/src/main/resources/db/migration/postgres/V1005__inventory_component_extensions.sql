-- Postgres-safe incremental adoption migration for remaining inventory component extensions.
-- Existing schemas are baselined at version 1000, so this runs only after baseline.
-- Empty schemas no-op here until V1011 creates the base tables.

DO $$
BEGIN
  IF to_regclass('inventory_components') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS software_identity_id UUID;

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS component_status VARCHAR(32);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS component_digest VARCHAR(120);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS normalized_name VARCHAR(500);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS normalized_version VARCHAR(255);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS software_model_result VARCHAR(500);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS last_observed_at TIMESTAMP WITH TIME ZONE;

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS retired_at TIMESTAMP WITH TIME ZONE;

  UPDATE inventory_components
  SET component_status = 'ACTIVE'
  WHERE component_status IS NULL;

  UPDATE inventory_components
  SET normalized_name = LOWER(package_name)
  WHERE (normalized_name IS NULL OR BTRIM(normalized_name) = '')
    AND package_name IS NOT NULL;

  UPDATE inventory_components
  SET normalized_name = 'unknown'
  WHERE normalized_name IS NULL
     OR BTRIM(normalized_name) = '';

  UPDATE inventory_components
  SET normalized_version = LOWER("version")
  WHERE (normalized_version IS NULL OR BTRIM(normalized_version) = '')
    AND "version" IS NOT NULL;

  UPDATE inventory_components
  SET normalized_version = 'unknown'
  WHERE normalized_version IS NULL
     OR BTRIM(normalized_version) = '';

  UPDATE inventory_components
  SET software_model_result = 'UNRESOLVED'
  WHERE software_model_result IS NULL
     OR BTRIM(software_model_result) = '';

  UPDATE inventory_components
  SET last_observed_at = ingested_at
  WHERE last_observed_at IS NULL
    AND ingested_at IS NOT NULL;

  UPDATE inventory_components
  SET last_observed_at = CURRENT_TIMESTAMP
  WHERE last_observed_at IS NULL;

  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inventory_component_digest ON inventory_components(component_digest)';
  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inventory_software_identity ON inventory_components(software_identity_id)';
END $$;
