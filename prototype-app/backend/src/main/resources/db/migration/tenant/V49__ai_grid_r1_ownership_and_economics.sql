-- AI Grid R1: explicit owner states and per-run evidence economics.

ALTER TABLE ai_security_artifacts
    ADD COLUMN IF NOT EXISTS owner_name varchar(255),
    ADD COLUMN IF NOT EXISTS owner_state varchar(32) NOT NULL DEFAULT 'UNOWNED',
    ADD COLUMN IF NOT EXISTS owner_source varchar(64),
    ADD COLUMN IF NOT EXISTS owner_confidence double precision,
    ADD COLUMN IF NOT EXISTS owner_confidence_method varchar(128),
    ADD COLUMN IF NOT EXISTS owner_confidence_method_version varchar(32),
    ADD COLUMN IF NOT EXISTS owner_updated_at timestamptz,
    ADD COLUMN IF NOT EXISTS business_criticality varchar(32),
    ADD COLUMN IF NOT EXISTS environment varchar(64);

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_owner_state_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_owner_state_check
    CHECK (owner_state IN ('CONFIRMED','INFERRED','CANDIDATE','UNOWNED'));
ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_owner_confidence_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_owner_confidence_check
    CHECK (owner_confidence IS NULL OR (owner_confidence >= 0 AND owner_confidence <= 1));

ALTER TABLE ai_grid_snapshot_bodies ADD COLUMN IF NOT EXISTS first_run_id uuid;

CREATE TABLE IF NOT EXISTS ai_grid_owner_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    previous_owner_name varchar(255),
    previous_owner_state varchar(32),
    owner_name varchar(255),
    owner_state varchar(32) NOT NULL,
    owner_source varchar(64),
    confidence double precision,
    confidence_method varchar(128),
    confidence_method_version varchar(32),
    actor varchar(255) NOT NULL,
    reason text,
    changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_run_metrics (
    run_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    completed_scope_count bigint NOT NULL DEFAULT 0,
    processing_duration_ms bigint NOT NULL DEFAULT 0,
    provider_api_calls bigint,
    provider_call_measurement_state varchar(32) NOT NULL DEFAULT 'UNAVAILABLE',
    artifact_count bigint NOT NULL DEFAULT 0,
    snapshot_manifest_count bigint NOT NULL DEFAULT 0,
    snapshot_bytes bigint NOT NULL DEFAULT 0,
    new_snapshot_bytes bigint NOT NULL DEFAULT 0,
    fact_count bigint NOT NULL DEFAULT 0,
    assessment_count bigint NOT NULL DEFAULT 0,
    pass_count bigint NOT NULL DEFAULT 0,
    fail_count bigint NOT NULL DEFAULT 0,
    no_decision_count bigint NOT NULL DEFAULT 0,
    open_gap_count bigint NOT NULL DEFAULT 0,
    first_inventory_at timestamptz,
    first_decision_at timestamptz,
    first_finding_at timestamptz,
    first_gap_at timestamptz,
    first_recorded_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_run_scope_metrics (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    scope_key varchar(512) NOT NULL,
    processing_duration_ms bigint NOT NULL CHECK (processing_duration_ms >= 0),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, scope_key)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_owner_history_artifact
    ON ai_grid_owner_history (artifact_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_run_metrics_updated
    ON ai_grid_run_metrics (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_run_scope_metrics_run
    ON ai_grid_run_scope_metrics (run_id);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_owner_history', 'ai_grid_run_metrics', 'ai_grid_run_scope_metrics'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                       table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;
