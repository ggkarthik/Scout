CREATE TABLE ${tenantSchema}.ai_security_copilot_studio_configs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    organization_url varchar(512) NOT NULL,
    credential_profile_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_security_azure_credential_profiles(id),
    discovery_enabled boolean NOT NULL DEFAULT false,
    execution_enabled boolean NOT NULL DEFAULT false,
    kill_switch boolean NOT NULL DEFAULT false,
    schedule_cron varchar(128) NOT NULL DEFAULT '0 0 * * * *',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, organization_url)
);
ALTER TABLE ${tenantSchema}.ai_security_copilot_studio_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_copilot_studio_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_copilot_studio_configs
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)));
