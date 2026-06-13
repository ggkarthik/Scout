-- Add group, license, and scope columns to inventory_components for SBOM enrichment
ALTER TABLE tenant_default.inventory_components
    ADD COLUMN IF NOT EXISTS package_group VARCHAR(255),
    ADD COLUMN IF NOT EXISTS license       TEXT,
    ADD COLUMN IF NOT EXISTS scope         VARCHAR(30);
