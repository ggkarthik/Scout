ALTER TABLE IF EXISTS software_identities
    ADD COLUMN IF NOT EXISTS vendor VARCHAR(255),
    ADD COLUMN IF NOT EXISTS product VARCHAR(255),
    ADD COLUMN IF NOT EXISTS product_hash VARCHAR(255),
    ADD COLUMN IF NOT EXISTS purl VARCHAR(1200),
    ADD COLUMN IF NOT EXISTS cpe23 VARCHAR(1200),
    ADD COLUMN IF NOT EXISTS vendor_product_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_software_identity_product_hash
    ON software_identities (product_hash)
    WHERE product_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_software_identity_cpe23
    ON software_identities (cpe23)
    WHERE cpe23 IS NOT NULL;

ALTER TABLE IF EXISTS identity_links
    ALTER COLUMN from_identifier_id DROP NOT NULL,
    ALTER COLUMN to_identifier_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(80),
    ADD COLUMN IF NOT EXISTS source_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS target_type VARCHAR(80),
    ADD COLUMN IF NOT EXISTS target_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS match_rule VARCHAR(40),
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_identity_links_source_target
    ON identity_links (source_type, source_id, target_type, target_id);

CREATE TABLE IF NOT EXISTS cis (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    sys_id VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    business_criticality VARCHAR(32) NOT NULL,
    environment VARCHAR(64),
    owner_email VARCHAR(255),
    last_inventory_at TIMESTAMPTZ,
    last_cmdb_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_cis_tenant_sys_id
    ON cis (tenant_id, sys_id);

CREATE UNIQUE INDEX IF NOT EXISTS uk_cis_asset_id
    ON cis (asset_id);

CREATE INDEX IF NOT EXISTS idx_cis_tenant_display
    ON cis (tenant_id, display_name);

CREATE TABLE IF NOT EXISTS ci_aliases (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    ci_id UUID NOT NULL REFERENCES cis(id),
    alias_name VARCHAR(255) NOT NULL,
    normalized_alias_name VARCHAR(255) NOT NULL,
    source_system VARCHAR(64) NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    confidence DOUBLE PRECISION
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_ci_aliases_tenant_alias_source
    ON ci_aliases (tenant_id, normalized_alias_name, source_system);

CREATE INDEX IF NOT EXISTS idx_ci_aliases_tenant_alias
    ON ci_aliases (tenant_id, normalized_alias_name);

CREATE TABLE IF NOT EXISTS discovery_models (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    primary_key VARCHAR(500) NOT NULL,
    normalization_status VARCHAR(80),
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    low_confidence BOOLEAN NOT NULL DEFAULT FALSE,
    normalized_product VARCHAR(255),
    normalized_publisher VARCHAR(255),
    normalized_version VARCHAR(255),
    product_hash VARCHAR(255),
    version_hash VARCHAR(255),
    full_version VARCHAR(255),
    platform VARCHAR(120),
    language VARCHAR(120),
    ml_model_version VARCHAR(120),
    display_name VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_discovery_models_tenant_primary_key
    ON discovery_models (tenant_id, primary_key);

CREATE INDEX IF NOT EXISTS idx_discovery_models_product_hash
    ON discovery_models (product_hash)
    WHERE product_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_discovery_models_version_hash
    ON discovery_models (version_hash)
    WHERE version_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS software_instances (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    ci_id UUID NOT NULL REFERENCES cis(id),
    discovery_model_id UUID REFERENCES discovery_models(id),
    software_identity_id UUID REFERENCES software_identities(id),
    inventory_component_id UUID REFERENCES inventory_components(id),
    display_name VARCHAR(500) NOT NULL,
    publisher VARCHAR(255),
    version VARCHAR(255),
    normalized_product VARCHAR(255) NOT NULL,
    normalized_publisher VARCHAR(255),
    normalized_version VARCHAR(255),
    install_date TIMESTAMPTZ,
    last_scanned TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    active_install BOOLEAN NOT NULL DEFAULT TRUE,
    unlicensed_install BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_model_pk VARCHAR(500),
    version_evidence VARCHAR(1000),
    source_system VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_software_instances_ci_product_version_evidence
    ON software_instances (ci_id, normalized_product, normalized_version, version_evidence);

CREATE INDEX IF NOT EXISTS idx_software_instances_ci
    ON software_instances (ci_id);

CREATE INDEX IF NOT EXISTS idx_software_instances_identity
    ON software_instances (software_identity_id);

ALTER TABLE IF EXISTS inventory_components
    ALTER COLUMN version DROP NOT NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'sbom_uploads_format_check'
  ) THEN
    ALTER TABLE sbom_uploads DROP CONSTRAINT sbom_uploads_format_check;
  END IF;
END $$;

ALTER TABLE sbom_uploads
    ADD CONSTRAINT sbom_uploads_format_check CHECK (
        format IN ('CYCLONEDX', 'SPDX', 'HOST_INVENTORY', 'UNKNOWN')
    );
