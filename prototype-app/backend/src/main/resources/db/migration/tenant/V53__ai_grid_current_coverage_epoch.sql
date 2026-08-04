-- R1: materialized multi-provider current coverage and dimensional reporting.

CREATE TABLE IF NOT EXISTS ai_grid_current_coverage_state (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    scope_head_count bigint NOT NULL DEFAULT 0,
    artifact_count bigint NOT NULL DEFAULT 0,
    candidate_count bigint NOT NULL DEFAULT 0,
    materialized_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_current_coverage_artifacts (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    technology_id varchar(128) NOT NULL DEFAULT 'UNCLASSIFIED',
    environment varchar(64) NOT NULL DEFAULT 'UNSPECIFIED',
    owner_name varchar(255) NOT NULL DEFAULT 'UNOWNED',
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_current_expected_candidates (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    technology_id varchar(128) NOT NULL,
    environment varchar(64) NOT NULL,
    owner_name varchar(255) NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    selection varchar(32) NOT NULL,
    framework_mappings_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    assessment_id uuid,
    applicability varchar(32),
    evidence_readiness varchar(32),
    decision varchar(32),
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_facts_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, artifact_id, policy_id)
);

ALTER TABLE ai_grid_policy_readiness ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;
ALTER TABLE ai_grid_coverage_gaps ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;
ALTER TABLE ai_grid_setup_actions ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;

CREATE INDEX IF NOT EXISTS idx_ai_grid_current_artifacts_epoch
    ON ai_grid_current_coverage_artifacts (epoch_id, provider, resource_family);
CREATE INDEX IF NOT EXISTS idx_ai_grid_current_candidates_epoch
    ON ai_grid_current_expected_candidates (epoch_id, provider, resource_family, policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_readiness_epoch
    ON ai_grid_policy_readiness (coverage_epoch_id, selection, readiness);
CREATE INDEX IF NOT EXISTS idx_ai_grid_coverage_gaps_epoch
    ON ai_grid_coverage_gaps (coverage_epoch_id, status, state);
CREATE INDEX IF NOT EXISTS idx_ai_grid_setup_actions_epoch
    ON ai_grid_setup_actions (coverage_epoch_id, status, priority);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_current_coverage_state',
        'ai_grid_current_coverage_artifacts',
        'ai_grid_current_expected_candidates'
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
