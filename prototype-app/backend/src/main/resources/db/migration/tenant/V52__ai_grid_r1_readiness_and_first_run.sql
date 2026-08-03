-- R1 managed-AI readiness, structured setup actions, and first-run utility telemetry.

ALTER TABLE ai_grid_snapshot_manifests
    ADD COLUMN IF NOT EXISTS connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_ai_grid_snapshot_manifest_connector
    ON ai_grid_snapshot_manifests (connector_config_id, created_at, run_id);

CREATE TABLE IF NOT EXISTS ai_grid_policy_readiness (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    selection varchar(32) NOT NULL,
    readiness varchar(32) NOT NULL,
    candidate_count bigint NOT NULL DEFAULT 0,
    applicable_count bigint NOT NULL DEFAULT 0,
    decision_required_count bigint NOT NULL DEFAULT 0,
    decision_ready_count bigint NOT NULL DEFAULT 0,
    no_decision_count bigint NOT NULL DEFAULT 0,
    error_count bigint NOT NULL DEFAULT 0,
    missing_assessment_count bigint NOT NULL DEFAULT 0,
    required_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    available_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    computed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id),
    CHECK (selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    CHECK (readiness IN ('READY','PARTIAL','BLOCKED','NOT_APPLICABLE','NO_RESOURCES'))
);

CREATE TABLE IF NOT EXISTS ai_grid_setup_actions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    policy_id varchar(128),
    fingerprint varchar(64) NOT NULL,
    priority integer NOT NULL,
    category varchar(32) NOT NULL,
    action_code varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    detail text NOT NULL,
    evidence_key varchar(512),
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, fingerprint),
    CHECK (priority BETWEEN 1 AND 100),
    CHECK (status IN ('OPEN','RESOLVED'))
);

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS expected_assessment_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS missing_assessment_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS decision_reachable_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_expected_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_decision_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS decision_reachability_percent double precision NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_utility_percent double precision NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS baseline_run boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS first_run_target_percent double precision NOT NULL DEFAULT 80,
    ADD COLUMN IF NOT EXISTS first_run_target_met boolean,
    ADD COLUMN IF NOT EXISTS first_owner_routed_finding_at timestamptz,
    ADD COLUMN IF NOT EXISTS first_exposure_hypothesis_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_readiness_run
    ON ai_grid_policy_readiness (run_id, selection, readiness);
CREATE INDEX IF NOT EXISTS idx_ai_grid_setup_actions_open
    ON ai_grid_setup_actions (run_id, status, priority, category);

ALTER TABLE ai_grid_policy_readiness ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_policy_readiness FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_policy_readiness;
CREATE POLICY tenant_isolation ON ai_grid_policy_readiness
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ai_grid_setup_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_setup_actions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_setup_actions;
CREATE POLICY tenant_isolation ON ai_grid_setup_actions
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
