-- migration-guard: tenant-only
--
-- Declared AI inventory: the models and datasets an uploaded AI-BOM says exist.
--
-- Deliberately a separate table rather than rows in ai_security_artifacts. That table holds
-- resources a connector observed in a cloud account, and the AI Grid assessment pipeline
-- evaluates its contents against policies written for provider-observed configuration.
-- Putting a document's claims there would have those policies assess a declaration as though
-- it were an observed deployment, which is the same mistake as correlating CVEs against a
-- model. Its account_id and region are also NOT NULL and have no meaning for a document.
--
-- A declared resource links to an artifact only once deployment is actually verified, and
-- until then it is exactly what it says: something a document declared.

CREATE TABLE ${tenantSchema}.ai_bom_declared_resources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    source_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_sources(id) ON DELETE CASCADE,
    -- Document version that last declared it, so a claim can be traced to its evidence.
    bom_id uuid NOT NULL,
    bom_component_id uuid,

    resource_kind varchar(16) NOT NULL,
    name varchar(512) NOT NULL,
    version varchar(255),

    -- How the resource is identified, in descending order of trustworthiness. A display name
    -- is never an identity: two unrelated models are routinely both called "classifier".
    identity_kind varchar(32) NOT NULL,
    identity_value varchar(1024) NOT NULL,

    -- A declaration is not a deployment. Nothing may present it as one until it has been
    -- matched to a connector-discovered resource or a reviewer has confirmed the mapping.
    deployment_state varchar(24) NOT NULL DEFAULT 'UNVERIFIED',
    linked_artifact_id uuid REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE SET NULL,
    link_method varchar(32),
    link_reviewed_by varchar(255),
    link_reviewed_at timestamptz,

    first_declared_at timestamptz NOT NULL DEFAULT now(),
    last_declared_at timestamptz NOT NULL DEFAULT now(),
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Scoped to the source, never global. The same model declared by two documents stays two
    -- declarations until something actually establishes they are the same thing; merging them
    -- on name would invent an equivalence the documents never asserted.
    UNIQUE (tenant_id, source_id, identity_value),

    CONSTRAINT ai_bom_declared_resource_kind_check
        CHECK (resource_kind IN ('MODEL', 'DATASET')),
    CONSTRAINT ai_bom_declared_resource_identity_kind_check
        CHECK (identity_kind IN ('DIGEST', 'VERSIONED_IDENTIFIER', 'SOURCE_SCOPED_REF')),
    CONSTRAINT ai_bom_declared_resource_deployment_state_check
        CHECK (deployment_state IN ('UNVERIFIED', 'LINKED', 'AMBIGUOUS')),
    CONSTRAINT ai_bom_declared_resource_link_method_check
        CHECK (link_method IS NULL OR link_method IN
            ('DIGEST_MATCH', 'VERSIONED_IDENTIFIER_MATCH', 'REVIEWED')),
    -- LINKED requires both the artifact and the method that justified the link, so a link can
    -- always be explained. Anything else must carry neither.
    CONSTRAINT ai_bom_declared_resource_link_consistency_check
        CHECK (
            (deployment_state = 'LINKED'
                AND linked_artifact_id IS NOT NULL AND link_method IS NOT NULL)
            OR (deployment_state <> 'LINKED'
                AND linked_artifact_id IS NULL AND link_method IS NULL)
        ),
    -- A reviewed link names its reviewer; an automatic match must not claim one.
    CONSTRAINT ai_bom_declared_resource_reviewer_check
        CHECK (
            (link_method = 'REVIEWED' AND link_reviewed_by IS NOT NULL)
            OR (link_method IS DISTINCT FROM 'REVIEWED' AND link_reviewed_by IS NULL)
        ),
    CONSTRAINT ai_bom_declared_resource_attributes_check
        CHECK (jsonb_typeof(attributes_json) = 'object')
);

CREATE INDEX idx_ai_bom_declared_resources_source
    ON ${tenantSchema}.ai_bom_declared_resources(tenant_id, source_id);
CREATE INDEX idx_ai_bom_declared_resources_kind
    ON ${tenantSchema}.ai_bom_declared_resources(tenant_id, resource_kind, deployment_state);
-- Drives the unlinked queue: everything awaiting verification or flagged ambiguous.
CREATE INDEX idx_ai_bom_declared_resources_unlinked
    ON ${tenantSchema}.ai_bom_declared_resources(tenant_id, deployment_state)
    WHERE deployment_state <> 'LINKED';

ALTER TABLE ${tenantSchema}.ai_bom_declared_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_declared_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_declared_resources
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
