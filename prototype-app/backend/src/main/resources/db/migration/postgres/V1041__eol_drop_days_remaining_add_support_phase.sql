-- Drop stale pre-computed column from both component tables.
-- eol_days_remaining is now computed live as (eol_date - CURRENT_DATE) at query time.
ALTER TABLE inventory_components DROP COLUMN IF EXISTS eol_days_remaining;
ALTER TABLE software_instances   DROP COLUMN IF EXISTS eol_days_remaining;

-- Add support_phase so it can be denormalized from the matched eol_release cycle.
ALTER TABLE inventory_components ADD COLUMN IF NOT EXISTS support_phase VARCHAR(30);
ALTER TABLE software_instances   ADD COLUMN IF NOT EXISTS support_phase VARCHAR(30);
