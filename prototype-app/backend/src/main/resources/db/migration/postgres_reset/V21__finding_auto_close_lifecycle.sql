ALTER TABLE tenant_default.findings
    ADD COLUMN IF NOT EXISTS last_observed_run_id uuid,
    ADD COLUMN IF NOT EXISTS consecutive_misses integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_close_eligible_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_by varchar(255),
    ADD COLUMN IF NOT EXISTS closed_reason varchar(80),
    ADD COLUMN IF NOT EXISTS closed_rule_id uuid;

CREATE INDEX IF NOT EXISTS idx_findings_auto_close_eligible
    ON tenant_default.findings (tenant_id, status, auto_close_eligible_at);

ALTER TABLE tenant_default.risk_policies
    ADD COLUMN IF NOT EXISTS auto_close_required_consecutive_misses integer NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS auto_close_not_observed_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_component_removed_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_asset_retired_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_source_disabled_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS auto_close_duplicate_enabled boolean NOT NULL DEFAULT true;
