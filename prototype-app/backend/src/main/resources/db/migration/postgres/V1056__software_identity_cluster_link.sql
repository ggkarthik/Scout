-- Cluster-level normalization override table.
-- One row per (tenant, source_type, source_key) links a discovery model cluster
-- or SBOM package cluster to a canonical software identity. Applying this link
-- cascades a bulk UPDATE to all matching software_instances / inventory_components,
-- resolving N quality issues in a single analyst action.
CREATE TABLE software_identity_cluster_link (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    source_type         varchar(40)  NOT NULL,   -- 'DISCOVERY_MODEL' | 'PACKAGE_PATTERN'
    source_key          varchar(500) NOT NULL,   -- dm.primary_key  OR  'ecosystem:package_name'
    target_identity_id  uuid NOT NULL REFERENCES software_identities(id),
    apply_to_future     boolean NOT NULL DEFAULT true,
    reason              varchar(400),
    confirmed_by        varchar(255),
    confirmed_at        timestamptz  NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    revoked_by          varchar(255)
);

-- Only one active link per cluster at a time (allow re-use after revoke).
CREATE UNIQUE INDEX uq_cluster_link_active
    ON software_identity_cluster_link (tenant_id, source_type, source_key)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_cluster_link_tenant
    ON software_identity_cluster_link (tenant_id)
    WHERE revoked_at IS NULL;
