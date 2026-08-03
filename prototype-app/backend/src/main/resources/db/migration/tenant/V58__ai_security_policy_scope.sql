CREATE TABLE IF NOT EXISTS ai_security_policy_scopes (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    mode varchar(32) NOT NULL DEFAULT 'ALL',
    condition_logic varchar(8) NOT NULL DEFAULT 'AND',
    conditions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_security_policy_artifact_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    policy_id varchar(128) NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    override varchar(16) NOT NULL,
    reason text,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_policy_parameters (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_security_policy_overrides_policy
    ON ai_security_policy_artifact_overrides (policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_security_policy_overrides_artifact
    ON ai_security_policy_artifact_overrides (artifact_id);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_security_policy_scopes',
        'ai_security_policy_artifact_overrides',
        'ai_security_policy_parameters'
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
