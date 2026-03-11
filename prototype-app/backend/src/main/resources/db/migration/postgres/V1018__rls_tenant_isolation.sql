-- BLG-007: PostgreSQL Row-Level Security for all tenant-scoped tables.
--
-- Policy: a row is visible / mutable when either:
--   (a) its tenant_id matches the current session's app.current_tenant_id, OR
--   (b) app.current_tenant_id is not set (migrations, background jobs, health checks).
--
-- FORCE ROW LEVEL SECURITY ensures the policy also applies to the table owner
-- (the application's DB user). Background tasks run without setting the variable,
-- which falls through to condition (b) and sees all rows — this is intentional for
-- the single-tenant prototype. In a production multi-tenant deployment, background
-- jobs must set the variable explicitly per tenant.

-- applicability_assessments
ALTER TABLE IF EXISTS applicability_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS applicability_assessments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON applicability_assessments;
CREATE POLICY rls_tenant ON applicability_assessments
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- assets
ALTER TABLE IF EXISTS assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON assets;
CREATE POLICY rls_tenant ON assets
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- component_vulnerability_states
ALTER TABLE IF EXISTS component_vulnerability_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS component_vulnerability_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON component_vulnerability_states;
CREATE POLICY rls_tenant ON component_vulnerability_states
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- findings
ALTER TABLE IF EXISTS findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON findings;
CREATE POLICY rls_tenant ON findings
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- inventory_components
ALTER TABLE IF EXISTS inventory_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS inventory_components FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON inventory_components;
CREATE POLICY rls_tenant ON inventory_components
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- inventory_component_cpe_map
ALTER TABLE IF EXISTS inventory_component_cpe_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS inventory_component_cpe_map FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON inventory_component_cpe_map;
CREATE POLICY rls_tenant ON inventory_component_cpe_map
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- investigations
ALTER TABLE IF EXISTS investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS investigations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON investigations;
CREATE POLICY rls_tenant ON investigations
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- org_cve_records
ALTER TABLE IF EXISTS org_cve_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS org_cve_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON org_cve_records;
CREATE POLICY rls_tenant ON org_cve_records
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- risk_policies
ALTER TABLE IF EXISTS risk_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS risk_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON risk_policies;
CREATE POLICY rls_tenant ON risk_policies
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- sbom_uploads
ALTER TABLE IF EXISTS sbom_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS sbom_uploads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON sbom_uploads;
CREATE POLICY rls_tenant ON sbom_uploads
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );

-- software_inventory_items
ALTER TABLE IF EXISTS software_inventory_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS software_inventory_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON software_inventory_items;
CREATE POLICY rls_tenant ON software_inventory_items
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );
