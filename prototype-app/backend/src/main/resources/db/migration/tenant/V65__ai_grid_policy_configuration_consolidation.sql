-- AI Grid is the sole owner of tenant policy configuration.  Backfill is
-- deliberately idempotent and rejects configuration for policies that never
-- reached the governed catalog before legacy state is removed.
CREATE TABLE IF NOT EXISTS ai_grid_policy_scopes (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    mode varchar(32) NOT NULL DEFAULT 'ALL',
    condition_logic varchar(8) NOT NULL DEFAULT 'AND',
    conditions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_artifact_overrides (
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

CREATE TABLE IF NOT EXISTS ai_grid_policy_parameters (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_overrides_policy ON ai_grid_policy_artifact_overrides (policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_overrides_artifact ON ai_grid_policy_artifact_overrides (artifact_id);

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['ai_grid_policy_scopes', 'ai_grid_policy_artifact_overrides', 'ai_grid_policy_parameters'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;

INSERT INTO ai_grid_policy_scopes (policy_id, tenant_id, mode, condition_logic, conditions_json, updated_by, updated_at)
SELECT s.policy_id, s.tenant_id, s.mode, s.condition_logic, s.conditions_json, s.updated_by, s.updated_at
  FROM ai_security_policy_scopes s
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id = s.policy_id AND p.lifecycle = 'PUBLISHED')
ON CONFLICT (policy_id) DO NOTHING;

INSERT INTO ai_grid_policy_artifact_overrides (id, tenant_id, policy_id, artifact_id, override, reason, created_by, created_at, updated_at)
SELECT o.id, o.tenant_id, o.policy_id, o.artifact_id, o.override, o.reason, o.created_by, o.created_at, o.updated_at
  FROM ai_security_policy_artifact_overrides o
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id = o.policy_id AND p.lifecycle = 'PUBLISHED')
ON CONFLICT (tenant_id, policy_id, artifact_id) DO NOTHING;

INSERT INTO ai_grid_policy_parameters (policy_id, tenant_id, parameters_json, updated_by, updated_at)
SELECT p.policy_id, p.tenant_id, p.parameters_json, p.updated_by, p.updated_at
  FROM ai_security_policy_parameters p
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions v WHERE v.policy_id = p.policy_id AND v.lifecycle = 'PUBLISHED')
ON CONFLICT (policy_id) DO NOTHING;

DO $migration$
BEGIN
    IF EXISTS (SELECT 1 FROM ai_security_policy_scopes s WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=s.policy_id AND p.lifecycle='PUBLISHED'))
       OR EXISTS (SELECT 1 FROM ai_security_policy_artifact_overrides o WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=o.policy_id AND p.lifecycle='PUBLISHED'))
       OR EXISTS (SELECT 1 FROM ai_security_policy_parameters x WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=x.policy_id AND p.lifecycle='PUBLISHED')) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI policy configuration with unmapped policy records';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_findings legacy
         LEFT JOIN findings canonical ON canonical.id = legacy.id
         WHERE canonical.id IS NULL
            OR canonical.policy_id IS DISTINCT FROM legacy.policy_id
            OR (legacy.status = 'OPEN' AND canonical.status <> 'OPEN')
            OR (legacy.status <> 'OPEN' AND canonical.status = 'OPEN')
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI findings before canonical finding state is verified';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_finding_reviews legacy
         LEFT JOIN finding_reviews canonical ON canonical.id = legacy.id
         WHERE canonical.id IS NULL
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI finding reviews before canonical review IDs are verified';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_findings legacy
         WHERE NOT EXISTS (
             SELECT 1 FROM finding_subjects subject
              WHERE subject.finding_id = legacy.id
                AND subject.subject_type = 'ARTIFACT'
                AND subject.subject_id = legacy.artifact_id
                AND subject.subject_role = 'PRIMARY'
         )
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI findings before canonical subjects are verified';
    END IF;
END
$migration$;

DROP TABLE ai_security_policy_artifact_overrides;
DROP TABLE ai_security_policy_parameters;
DROP TABLE ai_security_policy_scopes;
DROP TABLE ai_security_policy_settings;
DROP TABLE ai_security_policy_evaluations;
DROP TABLE ai_security_finding_reviews;
DROP TABLE ai_security_findings;
