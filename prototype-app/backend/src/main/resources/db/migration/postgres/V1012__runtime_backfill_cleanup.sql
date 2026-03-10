-- Move the last Postgres runtime schema/data repairs into Flyway so the app no
-- longer mutates schema on startup when running with the postgres profile.

DO $$
BEGIN
  IF to_regclass('public.sync_runs') IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sync_runs'
      AND column_name = 'records_failed'
  ) THEN
    ALTER TABLE public.sync_runs
      ADD COLUMN records_failed INTEGER;
  END IF;

  UPDATE public.sync_runs
  SET records_failed = 0
  WHERE records_failed IS NULL;

  ALTER TABLE public.sync_runs
    ALTER COLUMN records_failed SET DEFAULT 0;

  ALTER TABLE public.sync_runs
    ALTER COLUMN records_failed SET NOT NULL;
END $$;

DO $$
BEGIN
  IF to_regclass('public.inventory_components') IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'inventory_components'
      AND column_name = 'software_model_result'
  ) THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'inventory_components'
      AND column_name = 'software_model_id'
  ) THEN
    RETURN;
  END IF;

  IF to_regclass('public.software_models') IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'software_models'
      AND column_name = 'normalized_key'
  ) THEN
    RETURN;
  END IF;

  UPDATE public.inventory_components ic
  SET software_model_result = 'MATCHED:' || LOWER(sm.normalized_key)
  FROM public.software_models sm
  WHERE ic.software_model_id IS NOT NULL
    AND sm.id = ic.software_model_id
    AND (
      ic.software_model_result IS NULL
      OR BTRIM(ic.software_model_result) = ''
      OR ic.software_model_result = 'UNRESOLVED'
    );
END $$;
