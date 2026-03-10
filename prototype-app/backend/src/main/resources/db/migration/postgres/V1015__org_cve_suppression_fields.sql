ALTER TABLE IF EXISTS org_cve_records
    ADD COLUMN IF NOT EXISTS suppression_reason varchar(120),
    ADD COLUMN IF NOT EXISTS suppression_justification varchar(4000),
    ADD COLUMN IF NOT EXISTS suppressed_by varchar(255),
    ADD COLUMN IF NOT EXISTS suppressed_at timestamp with time zone,
    ADD COLUMN IF NOT EXISTS suppressed_until timestamp with time zone;

CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_suppressed_until
    ON org_cve_records (tenant_id, suppressed_until);
