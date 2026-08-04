-- AI Grid R0 integrity hardening: deterministic decisions and host-finding invariants.

ALTER TABLE ai_grid_assessments
    ADD COLUMN IF NOT EXISTS evaluation_as_of timestamptz,
    ADD COLUMN IF NOT EXISTS decision_fingerprint varchar(64);

UPDATE ai_grid_assessments
SET evaluation_as_of = evaluated_at
WHERE evaluation_as_of IS NULL;

ALTER TABLE ai_grid_assessments
    ALTER COLUMN evaluation_as_of SET NOT NULL;

CREATE TABLE IF NOT EXISTS ai_grid_relationship_snapshots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    source_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    target_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    relationship_type varchar(128) NOT NULL,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, run_id, source_artifact_id, target_artifact_id, relationship_type)
);

ALTER TABLE ai_grid_relationship_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_relationship_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_relationship_snapshots;
CREATE POLICY tenant_isolation ON ai_grid_relationship_snapshots
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_ai_grid_relationship_snapshots_source
    ON ai_grid_relationship_snapshots (run_id, source_artifact_id, relationship_type);

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_vulnerability_subject_check;
ALTER TABLE findings ADD CONSTRAINT findings_vulnerability_subject_check CHECK (
    finding_kind <> 'VULNERABILITY'
    OR (
        vulnerability_id IS NOT NULL
        AND (asset_id IS NOT NULL OR component_id IS NOT NULL)
    )
);
