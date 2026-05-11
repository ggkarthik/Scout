-- Drop execution_order from suppression_rules (UI removed, not needed)
ALTER TABLE suppression_rules DROP COLUMN IF EXISTS execution_order;

-- Add suppression rule reference columns to findings
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS suppressed_by_rule_id   UUID,
    ADD COLUMN IF NOT EXISTS suppressed_by_rule_name TEXT;
