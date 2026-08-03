-- Complete R2 temporal replay, durable membership decisions, and correlation epochs.

ALTER TABLE ai_grid_system_revisions
    ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;

ALTER TABLE ai_grid_exposure_paths
    ADD COLUMN IF NOT EXISTS last_complete_epoch_id uuid;

ALTER TABLE ai_grid_exposure_observations
    ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid,
    ADD COLUMN IF NOT EXISTS correlation_material_digest varchar(64);
DO $drop_observation_run_unique$
DECLARE constraint_name text;
BEGIN
    SELECT conname INTO constraint_name FROM pg_constraint
     WHERE conrelid='ai_grid_exposure_observations'::regclass AND contype='u'
       AND pg_get_constraintdef(oid) LIKE '%exposure_path_id%run_id%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE ai_grid_exposure_observations DROP CONSTRAINT %I', constraint_name);
    END IF;
END $drop_observation_run_unique$;
ALTER TABLE ai_grid_exposure_observations
    ADD CONSTRAINT uq_ai_grid_exposure_observation_epoch
    UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, run_id, coverage_epoch_id);

CREATE TABLE IF NOT EXISTS ai_grid_system_membership_overrides (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    decision varchar(16) NOT NULL CHECK (decision IN ('ACCEPT','REJECT')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, system_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_exposure_executions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    coverage_epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    evaluation_as_of timestamptz NOT NULL,
    correlation_versions_json jsonb NOT NULL,
    artifact_bindings_json jsonb NOT NULL,
    relationship_ids_json jsonb NOT NULL,
    host_fact_ids_json jsonb NOT NULL,
    system_revision_ids_json jsonb NOT NULL,
    material_digest varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, coverage_epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_execution_run
    ON ai_grid_exposure_executions (trigger_run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_system_revision_epoch
    ON ai_grid_system_revisions (coverage_epoch_id, system_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_observation_epoch
    ON ai_grid_exposure_observations (coverage_epoch_id, exposure_path_id);

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_system_membership_overrides', 'ai_grid_exposure_executions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END $rls$;
