-- AI Grid R0: immutable evidence, governed assessment state, and canonical findings.

-- Existing AI assessment and inventory rows are demo data. Connector configuration and
-- encrypted credentials are deliberately retained so inventory can be rebuilt by re-scan.
DELETE FROM ai_security_finding_reviews;
DELETE FROM ai_security_findings;
DELETE FROM ai_security_policy_evaluations;
DELETE FROM ai_security_policy_settings;
DELETE FROM ai_security_relationships;
DELETE FROM ai_security_artifact_sources;
DELETE FROM ai_security_artifacts;
DELETE FROM ai_security_observation_receipts;
DELETE FROM ai_security_snapshot_scopes;

CREATE TABLE IF NOT EXISTS ai_grid_snapshot_bodies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    content_hash varchar(64) NOT NULL,
    content_json jsonb NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    redaction_profile varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, content_hash)
);

CREATE TABLE IF NOT EXISTS ai_grid_snapshot_manifests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    scope_key varchar(512) NOT NULL,
    body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id),
    schema_version varchar(32) NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, artifact_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    fact_key varchar(255) NOT NULL,
    value_type varchar(32) NOT NULL,
    value_json jsonb,
    state varchar(32) NOT NULL CHECK (state IN ('KNOWN','UNKNOWN','ERROR','STALE')),
    provenance varchar(32) NOT NULL,
    evidence_class varchar(32) NOT NULL,
    source varchar(255) NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_until timestamptz,
    confidence_method varchar(128),
    confidence_method_version varchar(32),
    confidence double precision CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    derivation_inputs_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    fact_schema_version varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, artifact_id, fact_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_artifact_classifications (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    technology_id varchar(128) NOT NULL,
    capability varchar(128),
    primary_technology boolean NOT NULL DEFAULT false,
    state varchar(32) NOT NULL,
    registry_version varchar(32) NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    classified_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, artifact_id, technology_id, capability)
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_selections (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    selection varchar(32) NOT NULL CHECK (selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    updated_by varchar(255) NOT NULL,
    reason text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_selection_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    policy_id varchar(128) NOT NULL,
    previous_selection varchar(32),
    selection varchar(32) NOT NULL,
    actor varchar(255) NOT NULL,
    reason text,
    changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_assessments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    subject_type varchar(32) NOT NULL,
    subject_id uuid NOT NULL,
    snapshot_manifest_id uuid REFERENCES ai_grid_snapshot_manifests(id),
    selection varchar(32) NOT NULL,
    applicability varchar(32) NOT NULL,
    evidence_readiness varchar(32) NOT NULL,
    decision varchar(32) NOT NULL,
    reason_code varchar(128) NOT NULL,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint varchar(64) NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id, subject_type, subject_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_coverage_gaps (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fingerprint varchar(64) NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    policy_id varchar(128),
    state varchar(64) NOT NULL,
    reason text NOT NULL,
    required_action text,
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS ai_grid_systems (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    stable_key varchar(64) NOT NULL,
    name varchar(512) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    current_revision integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, stable_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_system_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    revision integer NOT NULL,
    membership_hash varchar(64) NOT NULL,
    source varchar(32) NOT NULL,
    rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, system_id, revision),
    UNIQUE (tenant_id, system_id, membership_hash)
);

CREATE TABLE IF NOT EXISTS ai_grid_system_memberships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_revision_id uuid NOT NULL REFERENCES ai_grid_system_revisions(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    membership_state varchar(32) NOT NULL,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, system_revision_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_type varchar(64) NOT NULL,
    aggregate_type varchar(64) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version varchar(64) NOT NULL,
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    status varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_type, aggregate_id, aggregate_version)
);

-- Generalize the canonical host finding without changing existing vulnerability rows.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS uk_findings_component_vulnerability;
ALTER TABLE findings ALTER COLUMN asset_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN component_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN vulnerability_id DROP NOT NULL;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_creation_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_creation_source_check
    CHECK (creation_source IN ('MANUAL','AUTOMATIC','AI_SECURITY'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_kind varchar(32) NOT NULL DEFAULT 'VULNERABILITY';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint varchar(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_class varchar(32);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS title varchar(512);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_id varchar(128);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_version varchar(32);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reason_code varchar(128);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assessment_id uuid;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_kind_check;
ALTER TABLE findings ADD CONSTRAINT findings_kind_check
    CHECK (finding_kind IN ('VULNERABILITY','AI_POSTURE','AI_EXPOSURE'));
CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_component_vulnerability
    ON findings (component_id, vulnerability_id)
    WHERE finding_kind = 'VULNERABILITY';
CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_tenant_fingerprint
    ON findings (tenant_id, fingerprint)
    WHERE fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS finding_subjects (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    subject_type varchar(32) NOT NULL,
    subject_id uuid NOT NULL,
    subject_revision varchar(64),
    subject_role varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, finding_id, subject_type, subject_id, subject_role)
);

CREATE TABLE IF NOT EXISTS finding_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL,
    reason text,
    policy_version varchar(32),
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_facts_current ON ai_grid_facts (artifact_id, fact_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_assessments_run ON ai_grid_assessments (run_id, decision);
CREATE INDEX IF NOT EXISTS idx_ai_grid_gaps_status ON ai_grid_coverage_gaps (status, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_outbox_work ON ai_grid_outbox (status, available_at, created_at);
CREATE INDEX IF NOT EXISTS idx_finding_subjects_subject ON finding_subjects (subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_finding ON finding_reviews (finding_id, reviewed_at DESC);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_snapshot_bodies', 'ai_grid_snapshot_manifests', 'ai_grid_facts',
        'ai_grid_artifact_classifications', 'ai_grid_policy_selections',
        'ai_grid_policy_selection_history', 'ai_grid_assessments', 'ai_grid_coverage_gaps',
        'ai_grid_systems', 'ai_grid_system_revisions', 'ai_grid_system_memberships',
        'ai_grid_outbox', 'finding_subjects', 'finding_reviews'
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
