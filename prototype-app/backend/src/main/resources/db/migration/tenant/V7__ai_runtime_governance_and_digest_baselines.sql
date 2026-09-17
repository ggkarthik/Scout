-- Append-only closure for AI runtime correlation, digest approvals, and connector rollout controls.
CREATE TABLE ${tenantSchema}.ai_security_artifact_digest_baselines (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    digest_kind varchar(64) NOT NULL,
    algorithm varchar(64) NOT NULL,
    key_version varchar(64) NOT NULL,
    approved_digest varchar(256) NOT NULL,
    approval_status varchar(32) NOT NULL,
    approved_by varchar(255),
    approved_at timestamptz,
    revoked_by varchar(255),
    revoked_at timestamptz,
    source_run_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_security_digest_baseline_kind_check
        CHECK (digest_kind IN ('PROMPT', 'TOOL_DEFINITION')),
    CONSTRAINT ai_security_digest_baseline_status_check
        CHECK (approval_status IN ('APPROVED', 'REVOKED')),
    UNIQUE (tenant_id, artifact_id, digest_kind)
);

ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_baselines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_artifact_digest_baselines
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE TABLE ${tenantSchema}.ai_security_artifact_digest_observations (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    digest_kind varchar(64) NOT NULL,
    algorithm varchar(64) NOT NULL,
    key_version varchar(64) NOT NULL,
    observed_digest varchar(256) NOT NULL,
    comparison_outcome varchar(64) NOT NULL,
    source_run_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id, digest_kind),
    CHECK (digest_kind IN ('PROMPT', 'TOOL_DEFINITION')),
    CHECK (comparison_outcome IN ('UNAPPROVED', 'UNCHANGED', 'CHANGED_AFTER_APPROVAL',
                                  'BASELINE_UNKNOWN_REAPPROVAL_REQUIRED'))
);
ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_artifact_digest_observations
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ai_agent_executions
    ADD COLUMN agent_version_artifact_id uuid REFERENCES ${tenantSchema}.ai_security_artifacts(id),
    ADD COLUMN provider_agent_digest varchar(256),
    ADD COLUMN provider_agent_version_digest varchar(256),
    ADD COLUMN correlation_status varchar(32) NOT NULL DEFAULT 'UNRESOLVED',
    ADD COLUMN correlation_diagnostic varchar(128),
    ADD CONSTRAINT ai_agent_execution_correlation_status_check
        CHECK (correlation_status IN ('RESOLVED', 'UNRESOLVED', 'NOT_APPLICABLE'));

ALTER TABLE ${tenantSchema}.ai_agent_execution_receipts
    ADD COLUMN execution_id uuid REFERENCES ${tenantSchema}.ai_agent_executions(id) ON DELETE CASCADE;

CREATE TABLE ${tenantSchema}.ai_agent_execution_participants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    execution_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_agent_executions(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    participant_role varchar(32) NOT NULL,
    evidence_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_agent_execution_participant_role_check
        CHECK (participant_role IN ('MODEL', 'TOOL', 'PROMPT', 'COMPONENT')),
    UNIQUE (tenant_id, execution_id, artifact_id, participant_role)
);

ALTER TABLE ${tenantSchema}.ai_agent_execution_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_participants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_agent_execution_participants
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
CREATE INDEX idx_ai_agent_execution_participants_execution
    ON ${tenantSchema}.ai_agent_execution_participants(execution_id, participant_role);

ALTER TABLE ${tenantSchema}.ai_security_connector_feature_flags
    ADD COLUMN updated_by varchar(255),
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE ${tenantSchema}.ai_security_copilot_studio_configs
    ADD COLUMN allowed_dataverse_hosts_json jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX idx_ai_security_digest_baselines_artifact
    ON ${tenantSchema}.ai_security_artifact_digest_baselines(artifact_id, approval_status);
