ALTER TABLE IF EXISTS org_cve_records
    ADD COLUMN IF NOT EXISTS matched_asset_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS applicable_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS impacted_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS not_affected_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fixed_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS no_patch_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS under_investigation_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unknown_component_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS review_reason character varying(120);

CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_review_reason
    ON org_cve_records(tenant_id, review_reason);
