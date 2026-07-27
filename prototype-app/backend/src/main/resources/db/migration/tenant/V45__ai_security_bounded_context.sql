CREATE TABLE IF NOT EXISTS ai_security_connector_configs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    role_arn varchar(512),
    external_id_ciphertext text,
    regions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, account_id)
);

CREATE TABLE IF NOT EXISTS ai_security_artifacts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    provider_resource_id varchar(1024) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    name varchar(512) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    deactivated_at timestamptz,
    UNIQUE (tenant_id, provider, provider_resource_id)
);

CREATE TABLE IF NOT EXISTS ai_security_artifact_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL,
    scope_key varchar(512) NOT NULL,
    run_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    evidence_hash varchar(128) NOT NULL,
    UNIQUE (tenant_id, artifact_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_security_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    source_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    target_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    relationship_type varchar(128) NOT NULL,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    scope_key varchar(512) NOT NULL,
    run_id uuid NOT NULL,
    active boolean NOT NULL DEFAULT true,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, source_artifact_id, target_artifact_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS ai_security_snapshot_scopes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    scope_key varchar(512) NOT NULL,
    status varchar(32) NOT NULL,
    expected_chunks integer NOT NULL DEFAULT 1,
    accepted_chunks integer NOT NULL DEFAULT 0,
    diagnostic_code varchar(64),
    diagnostic_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, run_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_security_observation_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    scope_key varchar(512) NOT NULL,
    chunk_sequence integer NOT NULL,
    idempotency_key varchar(256) NOT NULL,
    content_hash varchar(128) NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, scope_key, chunk_sequence),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS ai_security_policy_settings (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    enabled boolean NOT NULL,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_security_policy_evaluations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    outcome varchar(32) NOT NULL,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_findings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    display_id varchar(64) NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    severity varchar(32) NOT NULL,
    status varchar(32) NOT NULL,
    title varchar(512) NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    resolved_at timestamptz,
    UNIQUE (tenant_id, display_id),
    UNIQUE (tenant_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_finding_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES ai_security_findings(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL,
    reason text,
    policy_version varchar(32) NOT NULL,
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_security_artifacts_type_active
    ON ai_security_artifacts (artifact_type, active, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_artifacts_scope
    ON ai_security_artifacts (account_id, region, native_kind);
CREATE INDEX IF NOT EXISTS idx_ai_security_relationships_source
    ON ai_security_relationships (source_artifact_id, active);
CREATE INDEX IF NOT EXISTS idx_ai_security_relationships_target
    ON ai_security_relationships (target_artifact_id, active);
CREATE INDEX IF NOT EXISTS idx_ai_security_scopes_run_status
    ON ai_security_snapshot_scopes (run_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_security_evaluations_policy_outcome
    ON ai_security_policy_evaluations (policy_id, outcome, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_findings_status_severity
    ON ai_security_findings (status, severity, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_reviews_finding
    ON ai_security_finding_reviews (finding_id, reviewed_at DESC);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_security_connector_configs',
        'ai_security_artifacts',
        'ai_security_artifact_sources',
        'ai_security_relationships',
        'ai_security_snapshot_scopes',
        'ai_security_observation_receipts',
        'ai_security_policy_settings',
        'ai_security_policy_evaluations',
        'ai_security_findings',
        'ai_security_finding_reviews'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
            table_name
        );
    END LOOP;
END
$rls$;
