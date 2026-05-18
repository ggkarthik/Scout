ALTER TABLE github_sbom_sources
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

DO $$
DECLARE
    only_tenant UUID;
BEGIN
    IF (SELECT count(*) FROM tenants) = 1 THEN
        SELECT id INTO only_tenant FROM tenants ORDER BY created_at ASC LIMIT 1;
        UPDATE github_sbom_sources
        SET tenant_id = only_tenant
        WHERE tenant_id IS NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_github_sbom_sources_tenant
    ON github_sbom_sources (tenant_id, enabled, created_at);

ALTER TABLE sync_runs
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id),
    ADD COLUMN IF NOT EXISTS run_scope VARCHAR(64);

UPDATE sync_runs
SET run_scope = CASE
    WHEN upper(sync_type) IN ('SERVICENOW_CMDB', 'SCCM_CMDB', 'AWS_DISCOVERY', 'GITHUB_REPOSITORY_SBOM', 'GITHUB_GHCR_SBOM')
        THEN 'TENANT_INVENTORY'
    ELSE 'PLATFORM_VULNERABILITY'
END
WHERE run_scope IS NULL;

DO $$
DECLARE
    only_tenant UUID;
BEGIN
    IF (SELECT count(*) FROM tenants) = 1 THEN
        SELECT id INTO only_tenant FROM tenants ORDER BY created_at ASC LIMIT 1;
        UPDATE sync_runs
        SET tenant_id = only_tenant
        WHERE tenant_id IS NULL
          AND run_scope = 'TENANT_INVENTORY';
    END IF;
END $$;

ALTER TABLE sync_runs
    ALTER COLUMN run_scope SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sync_runs_scope_started
    ON sync_runs (run_scope, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant_type_started
    ON sync_runs (tenant_id, sync_type, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant_status_started
    ON sync_runs (tenant_id, status, started_at DESC);

ALTER TABLE github_sbom_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_sbom_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON github_sbom_sources;
CREATE POLICY rls_tenant ON github_sbom_sources
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON tenant_memberships;
CREATE POLICY rls_tenant ON tenant_memberships
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON service_accounts;
CREATE POLICY rls_tenant ON service_accounts
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE tenant_support_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_support_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON tenant_support_grants;
CREATE POLICY rls_tenant ON tenant_support_grants
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE servicenow_cmdb_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE servicenow_cmdb_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON servicenow_cmdb_configs;
CREATE POLICY rls_tenant ON servicenow_cmdb_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE sccm_cmdb_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sccm_cmdb_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON sccm_cmdb_configs;
CREATE POLICY rls_tenant ON sccm_cmdb_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE aws_discovery_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_discovery_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON aws_discovery_configs;
CREATE POLICY rls_tenant ON aws_discovery_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE aws_discovery_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_discovery_targets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON aws_discovery_targets;
CREATE POLICY rls_tenant ON aws_discovery_targets
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE vulnerability_source_filter_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_source_filter_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON vulnerability_source_filter_configs;
CREATE POLICY rls_tenant ON vulnerability_source_filter_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE applicability_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE applicability_assessments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON applicability_assessments;
CREATE POLICY rls_tenant ON applicability_assessments
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON assets;
CREATE POLICY rls_tenant ON assets
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE component_vulnerability_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE component_vulnerability_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON component_vulnerability_states;
CREATE POLICY rls_tenant ON component_vulnerability_states
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON findings;
CREATE POLICY rls_tenant ON findings
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE inventory_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_components FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON inventory_components;
CREATE POLICY rls_tenant ON inventory_components
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE inventory_component_cpe_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_component_cpe_map FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON inventory_component_cpe_map;
CREATE POLICY rls_tenant ON inventory_component_cpe_map
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON investigations;
CREATE POLICY rls_tenant ON investigations
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE org_cve_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_cve_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON org_cve_records;
CREATE POLICY rls_tenant ON org_cve_records
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE risk_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON risk_policies;
CREATE POLICY rls_tenant ON risk_policies
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE sbom_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom_uploads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON sbom_uploads;
CREATE POLICY rls_tenant ON sbom_uploads
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE software_inventory_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_inventory_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON software_inventory_items;
CREATE POLICY rls_tenant ON software_inventory_items
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON audit_events;
CREATE POLICY rls_tenant ON audit_events
    USING (
        tenant_id IS NULL
        OR tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
    );
