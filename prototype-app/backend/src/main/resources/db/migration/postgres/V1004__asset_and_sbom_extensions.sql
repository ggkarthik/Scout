-- Postgres-safe incremental adoption migration for asset and SBOM extension columns.

DO $$
BEGIN
  IF to_regclass('assets') IS NOT NULL THEN
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS service_name VARCHAR(255);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR(64);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_team VARCHAR(255);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_email VARCHAR(255);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_criticality VARCHAR(32);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS state VARCHAR(32);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_inventory_at TIMESTAMPTZ;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_cmdb_sync_at TIMESTAMPTZ;

    UPDATE assets
    SET business_criticality = COALESCE(business_criticality, 'MEDIUM'),
        state = COALESCE(state, 'ACTIVE');
  END IF;

  IF to_regclass('github_sbom_sources') IS NOT NULL THEN
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS path VARCHAR(1000);
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS asset_type VARCHAR(32);
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS asset_name VARCHAR(255);
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS asset_identifier VARCHAR(255);
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS frequency VARCHAR(32);
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS interval_minutes INTEGER;
    ALTER TABLE github_sbom_sources ADD COLUMN IF NOT EXISTS enabled BOOLEAN;

    UPDATE github_sbom_sources
    SET path = COALESCE(NULLIF(BTRIM(path), ''), 'dependency-graph/sbom'),
        asset_type = COALESCE(NULLIF(BTRIM(asset_type), ''), 'APPLICATION'),
        asset_name = COALESCE(NULLIF(BTRIM(asset_name), ''), owner || '/' || repo),
        asset_identifier = COALESCE(NULLIF(BTRIM(asset_identifier), ''), LOWER('github:' || owner || '/' || repo)),
        frequency = COALESCE(NULLIF(BTRIM(frequency), ''), 'ONCE'),
        interval_minutes = COALESCE(interval_minutes, 60),
        enabled = COALESCE(enabled, TRUE);
  END IF;

  IF to_regclass('sbom_uploads') IS NOT NULL THEN
    ALTER TABLE sbom_uploads ADD COLUMN IF NOT EXISTS status VARCHAR(32);

    UPDATE sbom_uploads
    SET status = COALESCE(NULLIF(BTRIM(status), ''), 'SUCCESS');
  END IF;
END $$;
