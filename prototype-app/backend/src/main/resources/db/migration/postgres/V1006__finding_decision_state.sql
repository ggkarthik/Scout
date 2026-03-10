-- Postgres-safe incremental adoption migration for finding decision state extensions.
-- Existing schemas are baselined at version 1000, so this runs only after baseline.
-- Empty schemas no-op here until V1011 creates the base tables.

DO $$
BEGIN
  IF to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS decision_state VARCHAR(40);

  ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS precedence_trace TEXT;

  UPDATE findings
  SET decision_state = 'AFFECTED'
  WHERE decision_state IS NULL
    AND status IN ('OPEN', 'SUPPRESSED', 'AUTO_CLOSED');

  UPDATE findings
  SET decision_state = 'NOT_AFFECTED'
  WHERE decision_state IS NULL
    AND status = 'RESOLVED';

  UPDATE findings
  SET decision_state = 'NEEDS_REVIEW'
  WHERE decision_state IS NULL;
END $$;
