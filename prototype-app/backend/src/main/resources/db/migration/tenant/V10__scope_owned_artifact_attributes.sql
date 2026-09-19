-- migration-guard: tenant-only
CREATE TABLE IF NOT EXISTS ${tenantSchema}.ai_security_artifact_attribute_ownership (
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    scope_key character varying(255) NOT NULL,
    attribute_key character varying(255) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT ai_security_artifact_attribute_ownership_pkey
        PRIMARY KEY (tenant_id, artifact_id, scope_key, attribute_key),
    CONSTRAINT ai_security_artifact_attribute_ownership_artifact_fkey
        FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE
);

ALTER TABLE ${tenantSchema}.ai_security_artifact_attribute_ownership ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_artifact_attribute_ownership FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation
    ON ${tenantSchema}.ai_security_artifact_attribute_ownership
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
