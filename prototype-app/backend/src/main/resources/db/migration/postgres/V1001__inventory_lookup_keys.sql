-- Postgres-safe incremental adoption migration.
-- Existing schemas are baselined at version 1000, so this runs only after baseline.
-- Empty schemas no-op here until V1011 creates the base tables.

DO $$
BEGIN
  IF to_regclass('inventory_components') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS normalized_purl VARCHAR(1200);

  ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS coord_key VARCHAR(500);

  UPDATE inventory_components
  SET normalized_purl = LOWER(purl)
  WHERE (normalized_purl IS NULL OR BTRIM(normalized_purl) = '')
    AND purl IS NOT NULL
    AND BTRIM(purl) <> '';

  UPDATE inventory_components
  SET coord_key = LOWER(ecosystem) || '::' || LOWER(package_name)
  WHERE (coord_key IS NULL OR BTRIM(coord_key) = '')
    AND ecosystem IS NOT NULL
    AND package_name IS NOT NULL;

  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inventory_norm_purl_tenant ON inventory_components(normalized_purl, tenant_id)';
  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inventory_coord_key_tenant ON inventory_components(coord_key, tenant_id)';
END $$;
