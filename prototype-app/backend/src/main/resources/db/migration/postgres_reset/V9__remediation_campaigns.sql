CREATE TABLE IF NOT EXISTS tenant_default.campaigns (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants (id),
    name varchar(255) NOT NULL,
    summary text,
    status varchar(32) NOT NULL,
    created_by varchar(255) NOT NULL,
    due_at timestamptz,
    started_at timestamptz,
    paused_at timestamptz,
    closed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_status_updated
    ON tenant_default.campaigns (tenant_id, status, updated_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_vulnerabilities (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    vulnerability_id uuid NOT NULL REFERENCES platform.vulnerabilities (id),
    external_id varchar(64) NOT NULL,
    title varchar(500),
    severity varchar(32),
    created_at timestamptz NOT NULL,
    CONSTRAINT uk_campaign_vulnerabilities_campaign_external UNIQUE (campaign_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_vulnerabilities_campaign
    ON tenant_default.campaign_vulnerabilities (campaign_id, external_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_notify_groups (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    group_name varchar(255) NOT NULL,
    role_label varchar(128),
    trigger_summary varchar(255),
    notifications_paused boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_notify_groups_campaign
    ON tenant_default.campaign_notify_groups (campaign_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_watchlist_entries (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    entry_type varchar(32) NOT NULL,
    label varchar(255) NOT NULL,
    email varchar(255),
    trigger_policy varchar(64),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_watchlist_entries_campaign
    ON tenant_default.campaign_watchlist_entries (campaign_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_notes (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    author varchar(255) NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_notes_campaign_created
    ON tenant_default.campaign_notes (campaign_id, created_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_activities (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    activity_type varchar(64) NOT NULL,
    actor varchar(255) NOT NULL,
    body text NOT NULL,
    metadata_json jsonb,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_activities_campaign_created
    ON tenant_default.campaign_activities (campaign_id, created_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_delivery_attempts (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    target_type varchar(32) NOT NULL,
    target_label varchar(255) NOT NULL,
    target_address varchar(255),
    subject varchar(500) NOT NULL,
    delivery_state varchar(32) NOT NULL,
    provider_message_id varchar(255),
    detail varchar(1000),
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_delivery_attempts_campaign_created
    ON tenant_default.campaign_delivery_attempts (campaign_id, created_at desc);
