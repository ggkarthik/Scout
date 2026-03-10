-- Postgres-safe compatibility migration for enum-backed varchar columns.
-- Existing schemas are baselined at version 1000, so this runs only after baseline.
-- New empty schemas still rely on Hibernate today; these statements are intentionally guarded.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'assets'
      AND column_name = 'type'
  ) THEN
    ALTER TABLE assets ALTER COLUMN "type" TYPE VARCHAR(32);
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'findings'
      AND column_name = 'status'
  ) THEN
    ALTER TABLE findings ALTER COLUMN status TYPE VARCHAR(32);
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'github_sbom_sources'
      AND column_name = 'asset_type'
  ) THEN
    ALTER TABLE github_sbom_sources ALTER COLUMN asset_type TYPE VARCHAR(32);
  END IF;
END $$;
