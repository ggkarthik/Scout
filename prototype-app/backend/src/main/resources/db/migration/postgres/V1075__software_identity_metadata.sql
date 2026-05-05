CREATE TABLE IF NOT EXISTS software_identity_metadata (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    software_identity_id uuid NOT NULL REFERENCES software_identities(id) ON DELETE CASCADE,
    owner varchar(255),
    support_group varchar(255),
    licensed varchar(64) NOT NULL DEFAULT 'Unknown',
    license_type varchar(255),
    recommendation text,
    recommendation_updated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_software_identity_metadata_tenant_identity UNIQUE (tenant_id, software_identity_id)
);

CREATE INDEX IF NOT EXISTS idx_software_identity_metadata_tenant
    ON software_identity_metadata (tenant_id);

CREATE INDEX IF NOT EXISTS idx_software_identity_metadata_identity
    ON software_identity_metadata (software_identity_id);
