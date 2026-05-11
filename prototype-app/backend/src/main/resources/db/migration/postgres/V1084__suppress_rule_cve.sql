-- V1084: Add suppressed-by-rule tracking to org_cve_records
ALTER TABLE org_cve_records
    ADD COLUMN IF NOT EXISTS suppressed_by_rule_id   UUID,
    ADD COLUMN IF NOT EXISTS suppressed_by_rule_name TEXT;
