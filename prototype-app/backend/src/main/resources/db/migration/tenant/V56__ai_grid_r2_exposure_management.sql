-- AI Grid R2: system lifecycle, host context ports, and bounded exposure correlation.

ALTER TABLE ai_grid_relationship_snapshots
    ADD COLUMN IF NOT EXISTS valid_from timestamptz,
    ADD COLUMN IF NOT EXISTS valid_until timestamptz;
UPDATE ai_grid_relationship_snapshots SET valid_from = observed_at WHERE valid_from IS NULL;
ALTER TABLE ai_grid_relationship_snapshots ALTER COLUMN valid_from SET NOT NULL;
ALTER TABLE ai_grid_relationship_snapshots ALTER COLUMN valid_from SET DEFAULT now();

ALTER TABLE ai_grid_systems
    ADD COLUMN IF NOT EXISTS root_artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS retired_at timestamptz;
ALTER TABLE ai_grid_system_revisions
    ADD COLUMN IF NOT EXISTS run_id uuid,
    ADD COLUMN IF NOT EXISTS valid_from timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_until timestamptz;
DO $drop_membership_hash_unique$
DECLARE constraint_name text;
BEGIN
    SELECT conname INTO constraint_name FROM pg_constraint
     WHERE conrelid='ai_grid_system_revisions'::regclass AND contype='u'
       AND pg_get_constraintdef(oid) LIKE '%membership_hash%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE ai_grid_system_revisions DROP CONSTRAINT %I', constraint_name);
    END IF;
END $drop_membership_hash_unique$;
ALTER TABLE ai_grid_system_memberships
    ADD COLUMN IF NOT EXISTS valid_from timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_until timestamptz,
    ADD COLUMN IF NOT EXISTS decided_by varchar(255),
    ADD COLUMN IF NOT EXISTS decided_at timestamptz;

CREATE TABLE IF NOT EXISTS ai_grid_system_lineage_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_type varchar(32) NOT NULL CHECK (event_type IN ('SPLIT','MERGED','RETIRED','SUCCESSOR')),
    run_id uuid,
    rationale text NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_grid_system_membership_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    resulting_revision_id uuid NOT NULL REFERENCES ai_grid_system_revisions(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    decision varchar(16) NOT NULL CHECK (decision IN ('ACCEPT','REJECT')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_grid_system_lineage_participants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_id uuid NOT NULL REFERENCES ai_grid_system_lineage_events(id) ON DELETE CASCADE,
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id) ON DELETE SET NULL,
    participant_role varchar(16) NOT NULL CHECK (participant_role IN ('PREDECESSOR','SUCCESSOR')),
    UNIQUE (tenant_id, event_id, system_id, participant_role)
);

CREATE TABLE IF NOT EXISTS ai_grid_host_context_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    fact_key varchar(255) NOT NULL,
    value_type varchar(32) NOT NULL,
    value_json jsonb,
    state varchar(32) NOT NULL CHECK (state IN ('KNOWN','UNKNOWN','ERROR','STALE')),
    provenance varchar(32) NOT NULL,
    evidence_class varchar(32) NOT NULL,
    source_port varchar(32) NOT NULL CHECK (source_port IN ('IDENTITY','DATA','REACHABILITY','ASSET','OWNERSHIP')),
    evidence_reference varchar(1024) NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, artifact_id, fact_key, source_port, observed_at)
);

CREATE TABLE IF NOT EXISTS ai_grid_exposure_paths (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fingerprint varchar(64) NOT NULL,
    correlation_id varchar(128) NOT NULL,
    correlation_version varchar(32) NOT NULL,
    root_cause_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id),
    canonical_path_signature varchar(64) NOT NULL,
    state varchar(32) NOT NULL CHECK (state IN ('EXPOSURE_HYPOTHESIS','VALIDATED_EXPOSURE','CLOSED')),
    status varchar(32) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
    severity varchar(32) NOT NULL,
    title varchar(512) NOT NULL,
    impact text NOT NULL,
    root_cause text NOT NULL,
    breakpoint text NOT NULL,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    validated_at timestamptz,
    closed_at timestamptz,
    last_complete_run_id uuid NOT NULL,
    finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    run_id uuid NOT NULL,
    state varchar(32) NOT NULL CHECK (state IN ('EXPOSURE_HYPOTHESIS','VALIDATED_EXPOSURE','ABSENT')),
    entry_artifact_id uuid REFERENCES ai_security_artifacts(id),
    system_id uuid REFERENCES ai_grid_systems(id),
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id),
    path_json jsonb NOT NULL,
    evidence_json jsonb NOT NULL,
    temporal_valid_from timestamptz NOT NULL,
    temporal_valid_until timestamptz,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, exposure_path_id, run_id)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_associations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    system_id uuid REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id) ON DELETE SET NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    association_role varchar(32) NOT NULL CHECK (association_role IN ('AFFECTED_SYSTEM','ENTRY_POINT','IMPACT','ROOT_CAUSE')),
    UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, system_id, artifact_id, association_role)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_dispositions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL CHECK (disposition IN ('ACCEPTED','REJECTED','RISK_ACCEPTED','NEEDS_EVIDENCE')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_current ON ai_grid_exposure_paths (status, state, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_observation_run ON ai_grid_exposure_observations (run_id, state);
CREATE INDEX IF NOT EXISTS idx_ai_grid_host_context_current ON ai_grid_host_context_facts (artifact_id, fact_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_lineage_system ON ai_grid_system_lineage_participants (system_id, participant_role);

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS graph_recomputed_node_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_recomputed_edge_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_traversed_path_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS exposure_path_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_recompute_duration_ms bigint NOT NULL DEFAULT 0;

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_system_lineage_events', 'ai_grid_system_lineage_participants',
        'ai_grid_system_membership_decisions',
        'ai_grid_host_context_facts', 'ai_grid_exposure_paths',
        'ai_grid_exposure_observations', 'ai_grid_exposure_associations',
        'ai_grid_exposure_dispositions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END $rls$;
