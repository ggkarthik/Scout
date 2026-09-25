-- migration-guard: tenant-only

ALTER TABLE ${tenantSchema}.ai_agent_executions
    ADD CONSTRAINT ai_agent_executions_approval_state_check
        CHECK (approval_state IS NULL OR approval_state IN
            ('APPROVED','DENIED','REQUIRED','NOT_REQUIRED','BYPASSED','UNKNOWN')) NOT VALID,
    ADD CONSTRAINT ai_agent_executions_policy_state_check
        CHECK (policy_state IS NULL OR policy_state IN
            ('ALLOWED','DENIED','BLOCKED','NOT_EVALUATED','UNKNOWN')) NOT VALID;

CREATE TABLE ${tenantSchema}.ai_grid_approved_agent_manifests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    agent_artifact_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    version_artifact_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    manifest_digest varchar(256) NOT NULL,
    components_json jsonb NOT NULL,
    approval_status varchar(32) NOT NULL,
    approved_by varchar(255),
    approved_at timestamptz,
    revoked_by varchar(255),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, version_artifact_id),
    CONSTRAINT ai_grid_approved_manifest_status_check
        CHECK (approval_status IN ('APPROVED', 'REVOKED')),
    CONSTRAINT ai_grid_approved_manifest_components_check
        CHECK (jsonb_typeof(components_json) = 'array')
);

CREATE TABLE ${tenantSchema}.ai_grid_component_allowlists (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    provider varchar(64) NOT NULL,
    component_kind varchar(64) NOT NULL,
    component_digest varchar(256) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'APPROVED',
    approved_by varchar(255) NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    revoked_by varchar(255),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, component_kind, component_digest),
    CONSTRAINT ai_grid_component_allowlist_status_check
        CHECK (status IN ('APPROVED', 'REVOKED'))
);

CREATE INDEX idx_ai_grid_approved_manifests_agent
    ON ${tenantSchema}.ai_grid_approved_agent_manifests(tenant_id, agent_artifact_id, approval_status);
CREATE INDEX idx_ai_grid_component_allowlists_lookup
    ON ${tenantSchema}.ai_grid_component_allowlists(tenant_id, provider, component_kind, status);

ALTER TABLE ${tenantSchema}.ai_grid_approved_agent_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_grid_approved_agent_manifests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_approved_agent_manifests
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ai_grid_component_allowlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_grid_component_allowlists FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_component_allowlists
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
