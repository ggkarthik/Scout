-- migration-guard: tenant-only
--
-- Stores the dependency and composition edges a BOM declares between its own components.
--
-- These are recorded verbatim and deliberately not interpreted. A CycloneDX dependsOn edge
-- states that one component depends on another; it does not state that a model was trained on
-- a dataset, or that a dataset is served at inference time. Inferring training or serving
-- usage from a generic edge would manufacture provenance claims the document never made, and
-- those claims would then feed policy decisions.
--
-- relationship_type therefore records only what the document structurally expressed.

CREATE TABLE ${tenantSchema}.bom_component_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    bom_id uuid NOT NULL,
    -- bom-ref values as they appear in the document. Kept as text rather than resolved to
    -- component ids because a document may reference a ref it never defines, and dropping
    -- those edges would silently lose structure the customer declared.
    source_ref text NOT NULL,
    target_ref text NOT NULL,
    source_component_id uuid,
    target_component_id uuid,
    relationship_type varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, bom_id, source_ref, target_ref, relationship_type),
    CONSTRAINT bom_component_relationship_type_check
        CHECK (relationship_type IN ('DEPENDS_ON', 'COMPOSED_OF'))
);

CREATE INDEX idx_bom_component_relationships_bom
    ON ${tenantSchema}.bom_component_relationships(tenant_id, bom_id);
CREATE INDEX idx_bom_component_relationships_source
    ON ${tenantSchema}.bom_component_relationships(tenant_id, source_component_id);

ALTER TABLE ${tenantSchema}.bom_component_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_component_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_component_relationships
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
