-- BOM ingestion tracking: one record per BOM file ingested, any type
CREATE TABLE IF NOT EXISTS tenant_default.bom_ingestion_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES platform.tenants(id),
    sbom_upload_id  UUID,
    asset_id        UUID,
    bom_type        VARCHAR(20)  NOT NULL,
    format          VARCHAR(20),
    format_version  VARCHAR(10),
    serial_number   TEXT,
    supplier        VARCHAR(255),
    source_method   VARCHAR(20)  NOT NULL DEFAULT 'URL',
    source_url      TEXT,
    component_count INTEGER      NOT NULL DEFAULT 0,
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    superseded_by   UUID,
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ingested_by     TEXT
);

CREATE INDEX IF NOT EXISTS idx_bom_ir_tenant        ON tenant_default.bom_ingestion_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_bom_ir_asset         ON tenant_default.bom_ingestion_records (asset_id);
CREATE INDEX IF NOT EXISTS idx_bom_ir_status_type   ON tenant_default.bom_ingestion_records (tenant_id, bom_type, status);
CREATE INDEX IF NOT EXISTS idx_bom_ir_ingested_at   ON tenant_default.bom_ingestion_records (tenant_id, ingested_at DESC);
