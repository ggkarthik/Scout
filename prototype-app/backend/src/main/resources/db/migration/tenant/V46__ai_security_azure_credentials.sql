CREATE TABLE IF NOT EXISTS ai_security_azure_credential_profiles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    name varchar(255) NOT NULL,
    auth_type varchar(32) NOT NULL,
    azure_tenant_id varchar(128) NOT NULL,
    client_id varchar(255),
    active_secret_ciphertext text,
    pending_secret_ciphertext text,
    active_secret_expires_at timestamptz,
    pending_secret_expires_at timestamptz,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    last_verified_at timestamptz,
    last_verification_status varchar(32),
    expiry_warning_days integer,
    created_by varchar(255) NOT NULL,
    updated_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by varchar(255),
    CONSTRAINT ai_security_azure_credential_auth_check
        CHECK (auth_type IN ('CLIENT_SECRET', 'WORKLOAD_FEDERATION', 'MANAGED_IDENTITY')),
    CONSTRAINT ai_security_azure_credential_status_check
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    UNIQUE (tenant_id, name)
);

ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS credential_profile_id uuid
        REFERENCES ai_security_azure_credential_profiles(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS source_config_id uuid,
    ADD COLUMN IF NOT EXISTS source_target_id uuid,
    ADD COLUMN IF NOT EXISTS provider_tenant_id varchar(128),
    ADD COLUMN IF NOT EXISTS resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_ai_security_azure_credentials_expiry
    ON ai_security_azure_credential_profiles (status, active_secret_expires_at);
CREATE INDEX IF NOT EXISTS idx_ai_security_connector_provider_target
    ON ai_security_connector_configs (provider, source_target_id);

ALTER TABLE ai_security_azure_credential_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_security_azure_credential_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_security_azure_credential_profiles;
CREATE POLICY tenant_isolation ON ai_security_azure_credential_profiles
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
