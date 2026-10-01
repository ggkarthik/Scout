-- migration-guard: tenant-only

ALTER TABLE ${tenantSchema}.tenant_ghsa_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.tenant_ghsa_integrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.tenant_ghsa_integrations
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.tenant_github_repository_component_advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.tenant_github_repository_component_advisories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.tenant_github_repository_component_advisories
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.tenant_ghsa_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.tenant_ghsa_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.tenant_ghsa_subscriptions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
