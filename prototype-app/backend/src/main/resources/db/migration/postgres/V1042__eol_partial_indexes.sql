-- Partial indexes to accelerate EOL/EOS filter queries on component tables.
-- Only indexes rows where the date is set, keeping index size small.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inv_comp_eol_date_partial
    ON inventory_components (eol_date)
    WHERE eol_date IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inv_comp_eol_support_end_partial
    ON inventory_components (eol_support_end_date)
    WHERE eol_support_end_date IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sw_inst_eol_date_partial
    ON software_instances (eol_date)
    WHERE eol_date IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sw_inst_eol_support_end_partial
    ON software_instances (eol_support_end_date)
    WHERE eol_support_end_date IS NOT NULL;
