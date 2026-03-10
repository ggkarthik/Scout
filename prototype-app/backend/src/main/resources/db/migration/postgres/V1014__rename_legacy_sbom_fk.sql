DO $$
BEGIN
  IF to_regclass('public.sbom_uploads') IS NULL THEN
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fkfl1rgtitudexg8bwkhoh2owyg'
      AND conrelid = 'public.sbom_uploads'::regclass
  ) AND NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fk_sbom_uploads_asset_id'
      AND conrelid = 'public.sbom_uploads'::regclass
  ) THEN
    ALTER TABLE public.sbom_uploads
      RENAME CONSTRAINT fkfl1rgtitudexg8bwkhoh2owyg TO fk_sbom_uploads_asset_id;
  END IF;
END $$;
