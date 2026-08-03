-- AI Grid R1: enforceable scan budgets, cadence, evidence retention, and provider-call accounting.

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS provider varchar(32),
    ADD COLUMN IF NOT EXISTS retained_snapshot_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS budget_state varchar(32) NOT NULL DEFAULT 'WITHIN_BUDGET';

ALTER TABLE ai_grid_snapshot_bodies
    ADD COLUMN IF NOT EXISTS retention_class varchar(32) NOT NULL DEFAULT 'HOT',
    ADD COLUMN IF NOT EXISTS retain_until timestamptz NOT NULL DEFAULT (now() + interval '90 days'),
    ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS replay_commitment_until timestamptz,
    ADD COLUMN IF NOT EXISTS retention_state varchar(32) NOT NULL DEFAULT 'RETAINED';

CREATE TABLE IF NOT EXISTS ai_grid_budget_config (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    enforcement_mode varchar(32) NOT NULL DEFAULT 'OBSERVE',
    daily_scan_limit bigint,
    daily_provider_api_call_limit bigint,
    daily_new_snapshot_bytes_limit bigint,
    daily_processing_ms_limit bigint,
    retained_snapshot_bytes_limit bigint,
    warning_ratio double precision NOT NULL DEFAULT 0.80,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (enforcement_mode IN ('OBSERVE','THROTTLE')),
    CHECK (daily_scan_limit IS NULL OR daily_scan_limit > 0),
    CHECK (daily_provider_api_call_limit IS NULL OR daily_provider_api_call_limit > 0),
    CHECK (daily_new_snapshot_bytes_limit IS NULL OR daily_new_snapshot_bytes_limit > 0),
    CHECK (daily_processing_ms_limit IS NULL OR daily_processing_ms_limit > 0),
    CHECK (retained_snapshot_bytes_limit IS NULL OR retained_snapshot_bytes_limit > 0),
    CHECK (warning_ratio > 0 AND warning_ratio < 1)
);

INSERT INTO ai_grid_budget_config
    (tenant_id, enforcement_mode, daily_scan_limit, daily_provider_api_call_limit,
     daily_new_snapshot_bytes_limit, daily_processing_ms_limit, retained_snapshot_bytes_limit,
     warning_ratio, updated_by, reason)
VALUES ('${tenantId}'::uuid, 'OBSERVE', 24, 10000, 1073741824, 3600000, 10737418240,
        0.80, 'ai-grid-bootstrap', 'Initial observable AI Grid budget')
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS ai_grid_scan_cadence_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    resource_family varchar(128) NOT NULL DEFAULT '*',
    environment varchar(64) NOT NULL DEFAULT '*',
    criticality varchar(32) NOT NULL DEFAULT '*',
    minimum_interval_seconds bigint NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, resource_family, environment, criticality),
    CHECK (minimum_interval_seconds >= 0)
);

CREATE TABLE IF NOT EXISTS ai_grid_budget_admissions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    decision varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    usage_json jsonb NOT NULL,
    admitted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id),
    CHECK (decision IN ('ADMITTED','THROTTLED'))
);

CREATE TABLE IF NOT EXISTS ai_grid_budget_alerts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid,
    metric varchar(64) NOT NULL,
    level varchar(32) NOT NULL,
    observed_value bigint NOT NULL,
    limit_value bigint NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_by varchar(255),
    acknowledged_at timestamptz,
    CHECK (level IN ('WARNING','EXCEEDED')),
    CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED'))
);

CREATE TABLE IF NOT EXISTS ai_grid_retention_policies (
    retention_class varchar(32) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    retain_days integer NOT NULL,
    archive_after_days integer,
    restricted boolean NOT NULL DEFAULT false,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (retention_class IN ('HOT','ARCHIVE','RESTRICTED_EVIDENCE')),
    CHECK (retain_days > 0),
    CHECK (archive_after_days IS NULL OR (archive_after_days >= 0 AND archive_after_days < retain_days))
);

INSERT INTO ai_grid_retention_policies
    (retention_class, tenant_id, retain_days, archive_after_days, restricted, updated_by, reason)
VALUES
    ('HOT', '${tenantId}'::uuid, 90, 30, false, 'ai-grid-bootstrap', 'Default replay retention'),
    ('ARCHIVE', '${tenantId}'::uuid, 365, null, false, 'ai-grid-bootstrap', 'Extended archive retention'),
    ('RESTRICTED_EVIDENCE', '${tenantId}'::uuid, 30, null, true, 'ai-grid-bootstrap', 'Restricted evidence retention')
ON CONFLICT (retention_class) DO NOTHING;

CREATE TABLE IF NOT EXISTS ai_grid_evidence_holds (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id) ON DELETE CASCADE,
    hold_type varchar(32) NOT NULL,
    reference_id varchar(255) NOT NULL,
    reason text NOT NULL,
    expires_at timestamptz,
    released_at timestamptz,
    released_by varchar(255),
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, snapshot_body_id, hold_type, reference_id),
    CHECK (hold_type IN ('ACTIVE_FINDING','EXCEPTION','LEGAL_HOLD','REPLAY_COMMITMENT'))
);

CREATE TABLE IF NOT EXISTS ai_grid_retention_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id) ON DELETE CASCADE,
    decision varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, snapshot_body_id, evaluated_at),
    CHECK (decision IN ('RETAIN','ARCHIVE','PURGE_BLOCKED','PURGE_ELIGIBLE'))
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_admissions_day
    ON ai_grid_budget_admissions (admitted_at DESC, provider);
CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_alerts_open
    ON ai_grid_budget_alerts (status, level);
CREATE UNIQUE INDEX IF NOT EXISTS uk_ai_grid_budget_alert_open_metric
    ON ai_grid_budget_alerts (tenant_id, metric)
    WHERE status IN ('OPEN','ACKNOWLEDGED');
CREATE INDEX IF NOT EXISTS idx_ai_grid_snapshot_retention
    ON ai_grid_snapshot_bodies (retention_state, retain_until);
CREATE INDEX IF NOT EXISTS idx_ai_grid_evidence_holds_body
    ON ai_grid_evidence_holds (snapshot_body_id, released_at, expires_at);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_budget_config', 'ai_grid_scan_cadence_rules', 'ai_grid_budget_admissions',
        'ai_grid_budget_alerts', 'ai_grid_retention_policies', 'ai_grid_evidence_holds',
        'ai_grid_retention_decisions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid', table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;
