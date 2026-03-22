ALTER TABLE IF EXISTS component_vulnerability_states
    ADD COLUMN IF NOT EXISTS selected_target_source TEXT;

CREATE TABLE IF NOT EXISTS dashboard_noise_reduction_projection (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    never_opened_not_applicable BIGINT NOT NULL DEFAULT 0,
    deferred_under_investigation BIGINT NOT NULL DEFAULT 0,
    category_counts_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_noise_reduction_projection_last_computed
    ON dashboard_noise_reduction_projection (last_computed_at DESC);
