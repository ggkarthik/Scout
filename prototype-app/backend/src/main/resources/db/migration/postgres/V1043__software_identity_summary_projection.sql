CREATE TABLE IF NOT EXISTS software_identity_summary (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    software_identity_id UUID NOT NULL REFERENCES software_identities(id) ON DELETE CASCADE,
    display_name TEXT,
    canonical_key TEXT,
    vendor TEXT,
    product TEXT,
    normalized_key TEXT NOT NULL,
    purl TEXT,
    cpe23 TEXT,
    asset_types TEXT[] NOT NULL DEFAULT '{}',
    ecosystems TEXT[] NOT NULL DEFAULT '{}',
    source_systems TEXT[] NOT NULL DEFAULT '{}',
    eol_slug TEXT,
    mapping_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    needs_eol_mapping BOOLEAN NOT NULL DEFAULT FALSE,
    asset_count BIGINT NOT NULL DEFAULT 0,
    component_count BIGINT NOT NULL DEFAULT 0,
    version_count BIGINT NOT NULL DEFAULT 0,
    eol_component_count BIGINT NOT NULL DEFAULT 0,
    near_eol_component_count BIGINT NOT NULL DEFAULT 0,
    unknown_eol_component_count BIGINT NOT NULL DEFAULT 0,
    last_observed_at TIMESTAMPTZ,
    summary_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, software_identity_id)
);

CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_component_count
    ON software_identity_summary (tenant_id, component_count DESC, display_name);

CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_mapping
    ON software_identity_summary (tenant_id, needs_eol_mapping, mapping_confirmed);

CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_lifecycle
    ON software_identity_summary (
        tenant_id,
        eol_component_count DESC,
        near_eol_component_count DESC,
        unknown_eol_component_count DESC
    );

CREATE INDEX IF NOT EXISTS idx_software_identity_summary_normalized_key
    ON software_identity_summary (normalized_key);
