-- Repair legacy reset migrations V3/V4, which created these derived tables in
-- public. Projection data is rebuildable, so every tenant receives a clean,
-- schema-local and RLS-protected copy.

-- demo_requests is a pre-tenant control-plane workflow. Its existing tenant_id
-- records the tenant provisioned after approval, so it cannot also serve as an
-- isolation discriminator before that tenant exists. Keep this explicit
-- exemption until the table is moved to the platform schema.
ALTER TABLE demo_requests ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE demo_requests ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE demo_requests DISABLE ROW LEVEL SECURITY;
ALTER TABLE demo_requests NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON demo_requests;

-- Audit events also include pre-authentication/platform events for which no
-- tenant exists. Keep tenant events isolated while allowing only null-context
-- callers to write and read null-tenant audit rows.
ALTER TABLE audit_events ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE audit_events ALTER COLUMN tenant_id DROP DEFAULT;
DROP POLICY IF EXISTS tenant_isolation ON audit_events;
CREATE POLICY tenant_isolation ON audit_events
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id', true), '') IS NULL)
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id', true), '') IS NULL)
    );

-- Findings may be linked directly to an asset or indirectly through a
-- component. Preserve the supported direct-asset path.
ALTER TABLE findings ALTER COLUMN component_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN asset_id DROP NOT NULL;

CREATE TABLE IF NOT EXISTS finding_list_projection (
    finding_id uuid PRIMARY KEY,
    display_id varchar(32),
    severity varchar(32),
    status varchar(32) NOT NULL,
    decision_state varchar(64),
    creation_source varchar(32),
    match_method varchar(64),
    vex_status varchar(64),
    vex_freshness varchar(64),
    vex_provider varchar(128),
    confidence_score double precision,
    vulnerability_id varchar(64),
    package_name varchar(255),
    ecosystem varchar(64),
    owner_group varchar(255),
    assigned_to varchar(255),
    incident_id varchar(64),
    due_at timestamptz,
    asset_name varchar(255),
    support_group varchar(255),
    patch_available boolean NOT NULL,
    suppressed_until timestamptz,
    risk_score double precision NOT NULL,
    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    first_observed_at timestamptz,
    tenant_id uuid
);

CREATE TABLE IF NOT EXISTS finding_workspace_projection_status (
    projection_key varchar(64) PRIMARY KEY,
    last_computed_at timestamptz NOT NULL,
    finding_count bigint NOT NULL,
    source_finding_count bigint NOT NULL DEFAULT 0,
    last_rebuild_duration_ms bigint,
    tenant_id uuid
);

ALTER TABLE finding_list_projection ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE finding_workspace_projection_status ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS source_finding_count bigint NOT NULL DEFAULT 0;
ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS last_rebuild_duration_ms bigint;

UPDATE finding_list_projection SET tenant_id = '${tenantId}'::uuid WHERE tenant_id IS NULL;
UPDATE finding_workspace_projection_status SET tenant_id = '${tenantId}'::uuid WHERE tenant_id IS NULL;

ALTER TABLE finding_list_projection ALTER COLUMN tenant_id SET DEFAULT '${tenantId}'::uuid;
ALTER TABLE finding_list_projection ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE finding_workspace_projection_status ALTER COLUMN tenant_id SET DEFAULT '${tenantId}'::uuid;
ALTER TABLE finding_workspace_projection_status ALTER COLUMN tenant_id SET NOT NULL;

DO $constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'finding_list_projection'::regclass
          AND conname = 'finding_list_projection_tenant_id_fkey'
    ) THEN
        ALTER TABLE finding_list_projection
            ADD CONSTRAINT finding_list_projection_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'finding_workspace_projection_status'::regclass
          AND conname = 'finding_workspace_projection_status_tenant_id_fkey'
    ) THEN
        ALTER TABLE finding_workspace_projection_status
            ADD CONSTRAINT finding_workspace_projection_status_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);
    END IF;
END
$constraints$;

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_status_due
    ON finding_list_projection (status, due_at);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_assigned_status
    ON finding_list_projection (assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_owner_status
    ON finding_list_projection (owner_group, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_incident_status
    ON finding_list_projection (incident_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_suppressed_status
    ON finding_list_projection (suppressed_until, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_updated_tiebreak
    ON finding_list_projection (updated_at, finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_severity_status
    ON finding_list_projection (severity, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_support_status
    ON finding_list_projection (support_group, status);
CREATE INDEX IF NOT EXISTS idx_finding_list_projection_patch_status
    ON finding_list_projection (patch_available, status);

ALTER TABLE finding_list_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_list_projection FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON finding_list_projection;
CREATE POLICY tenant_isolation ON finding_list_projection
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE finding_workspace_projection_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_workspace_projection_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON finding_workspace_projection_status;
CREATE POLICY tenant_isolation ON finding_workspace_projection_status
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
