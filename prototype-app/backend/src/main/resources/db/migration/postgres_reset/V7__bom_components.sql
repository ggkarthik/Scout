-- Per-component rows enriched with BOM type metadata
CREATE TABLE IF NOT EXISTS tenant_default.bom_components (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bom_id         UUID NOT NULL,
    tenant_id      UUID NOT NULL REFERENCES platform.tenants(id),
    name           TEXT NOT NULL,
    version        TEXT,
    purl           TEXT,
    cpe            TEXT,
    license        TEXT,
    supplier       TEXT,
    component_type VARCHAR(40),
    category       VARCHAR(30) NOT NULL DEFAULT 'UNMATCHED',
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    hashes         JSONB,
    properties     JSONB
);

CREATE INDEX IF NOT EXISTS idx_bom_comp_bom_id   ON tenant_default.bom_components (bom_id);
CREATE INDEX IF NOT EXISTS idx_bom_comp_tenant   ON tenant_default.bom_components (tenant_id);
CREATE INDEX IF NOT EXISTS idx_bom_comp_active   ON tenant_default.bom_components (bom_id, is_active);
CREATE INDEX IF NOT EXISTS idx_bom_comp_purl     ON tenant_default.bom_components (purl) WHERE purl IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bom_comp_cpe      ON tenant_default.bom_components (cpe)  WHERE cpe  IS NOT NULL;
