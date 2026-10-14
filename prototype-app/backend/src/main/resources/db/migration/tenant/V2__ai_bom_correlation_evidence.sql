-- Association support is independent of canonical finding workflow status.
ALTER TABLE ${tenantSchema}.ai_bom_resource_vulnerability_links
    ADD COLUMN status varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED')),
    ADD COLUMN confirmed_at timestamptz,
    ADD COLUMN retired_at timestamptz,
    ADD COLUMN retirement_reason varchar(64),
    ADD COLUMN lifecycle_history jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(lifecycle_history) = 'array');

CREATE TABLE ${tenantSchema}.ai_bom_correlation_paths (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    declared_resource_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_bom_declared_resources(id) ON DELETE CASCADE,
    link_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_bom_resource_vulnerability_links(id) ON DELETE CASCADE,
    source_id uuid NOT NULL,
    bom_id uuid NOT NULL,
    source_revision bigint NOT NULL,
    component_ids jsonb NOT NULL CHECK (jsonb_typeof(component_ids) = 'array'),
    relationship_ids jsonb NOT NULL CHECK (jsonb_typeof(relationship_ids) = 'array'),
    component_refs jsonb NOT NULL CHECK (jsonb_typeof(component_refs) = 'array'),
    relationship_keys jsonb NOT NULL CHECK (jsonb_typeof(relationship_keys) = 'array'),
    terminal_component_id uuid REFERENCES ${tenantSchema}.inventory_components(id) ON DELETE SET NULL,
    match_method varchar(32) NOT NULL,
    fingerprint varchar(64) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED')),
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    retirement_reason varchar(64),
    lifecycle_history jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(lifecycle_history) = 'array'),
    UNIQUE (tenant_id, declared_resource_id, link_id, fingerprint)
);
CREATE INDEX idx_ai_bom_paths_resource ON ${tenantSchema}.ai_bom_correlation_paths(tenant_id, declared_resource_id, status);
CREATE INDEX idx_ai_bom_paths_link ON ${tenantSchema}.ai_bom_correlation_paths(link_id, status);

CREATE TABLE ${tenantSchema}.ai_bom_correlation_gaps (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    declared_resource_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_bom_declared_resources(id) ON DELETE CASCADE,
    source_id uuid NOT NULL,
    bom_id uuid,
    source_revision bigint NOT NULL,
    component_id uuid,
    component_ref text,
    reason varchar(64) NOT NULL,
    fingerprint varchar(64) NOT NULL,
    detected_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, declared_resource_id, fingerprint)
);
CREATE INDEX idx_ai_bom_gaps_resource ON ${tenantSchema}.ai_bom_correlation_gaps(tenant_id, declared_resource_id, resolved_at);

ALTER TABLE ${tenantSchema}.ai_bom_correlation_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_correlation_paths FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_correlation_paths
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
ALTER TABLE ${tenantSchema}.ai_bom_correlation_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_correlation_gaps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_correlation_gaps
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
