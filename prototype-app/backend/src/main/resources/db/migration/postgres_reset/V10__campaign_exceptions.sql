ALTER TABLE tenant_default.campaign_watchlist_entries
    ADD COLUMN IF NOT EXISTS trigger_policy varchar(64);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_exceptions (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    finding_display_id varchar(64),
    asset_name varchar(255),
    package_name varchar(255),
    title varchar(255) NOT NULL,
    reason text NOT NULL,
    status varchar(32) NOT NULL,
    requested_by varchar(255) NOT NULL,
    requested_at timestamptz NOT NULL,
    decision_due_at timestamptz,
    decisioned_by varchar(255),
    decisioned_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_exceptions_campaign_requested
    ON tenant_default.campaign_exceptions (campaign_id, requested_at desc);
