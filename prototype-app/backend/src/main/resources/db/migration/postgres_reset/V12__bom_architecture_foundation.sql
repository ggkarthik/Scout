ALTER TABLE tenant_default.bom_ingestion_records
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(40) NOT NULL DEFAULT 'URL',
    ADD COLUMN IF NOT EXISTS source_system VARCHAR(80),
    ADD COLUMN IF NOT EXISTS source_reference TEXT,
    ADD COLUMN IF NOT EXISTS source_endpoint TEXT,
    ADD COLUMN IF NOT EXISTS source_label TEXT,
    ADD COLUMN IF NOT EXISTS spec_family VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS document_format VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS document_name TEXT,
    ADD COLUMN IF NOT EXISTS content_type VARCHAR(120),
    ADD COLUMN IF NOT EXISTS content_length_bytes BIGINT,
    ADD COLUMN IF NOT EXISTS checksum_sha256 VARCHAR(128),
    ADD COLUMN IF NOT EXISTS previous_bom_id UUID;

UPDATE tenant_default.bom_ingestion_records
SET source_type = COALESCE(NULLIF(source_method, ''), 'URL')
WHERE source_type IS NULL OR source_type = '';

UPDATE tenant_default.bom_ingestion_records
SET source_reference = COALESCE(source_reference, source_url)
WHERE source_reference IS NULL;

UPDATE tenant_default.bom_ingestion_records
SET source_system = COALESCE(
    source_system,
    CASE
        WHEN source_method IN ('URL', 'UPLOAD') THEN 'manual'
        ELSE LOWER(source_method)
    END
)
WHERE source_system IS NULL;

UPDATE tenant_default.bom_ingestion_records
SET spec_family = CASE
    WHEN format = 'CYCLONEDX' THEN 'CYCLONEDX'
    WHEN format = 'SPDX' THEN 'SPDX'
    ELSE 'UNKNOWN'
END
WHERE spec_family IS NULL OR spec_family = 'UNKNOWN';

UPDATE tenant_default.bom_ingestion_records
SET document_name = COALESCE(document_name, source_reference)
WHERE document_name IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_schema = 'tenant_default'
          AND table_name = 'bom_ingestion_records'
          AND constraint_name = 'fk_bom_ir_previous_bom'
    ) THEN
        ALTER TABLE tenant_default.bom_ingestion_records
            ADD CONSTRAINT fk_bom_ir_previous_bom
            FOREIGN KEY (previous_bom_id)
            REFERENCES tenant_default.bom_ingestion_records(id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_bom_ir_source_type
    ON tenant_default.bom_ingestion_records (tenant_id, source_type, status);
CREATE INDEX IF NOT EXISTS idx_bom_ir_source_system
    ON tenant_default.bom_ingestion_records (tenant_id, source_system);
CREATE INDEX IF NOT EXISTS idx_bom_ir_spec_family
    ON tenant_default.bom_ingestion_records (tenant_id, spec_family, format_version);

ALTER TABLE tenant_default.bom_components
    ADD COLUMN IF NOT EXISTS bom_ref TEXT,
    ADD COLUMN IF NOT EXISTS group_name TEXT,
    ADD COLUMN IF NOT EXISTS scope TEXT,
    ADD COLUMN IF NOT EXISTS swid TEXT,
    ADD COLUMN IF NOT EXISTS external_references JSONB,
    ADD COLUMN IF NOT EXISTS workflow_status VARCHAR(40) NOT NULL DEFAULT 'DISCOVERED';

UPDATE tenant_default.bom_components
SET group_name = supplier
WHERE group_name IS NULL AND supplier IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_evidence (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    bom_id           UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    evidence_type    VARCHAR(40) NOT NULL,
    evidence_key     TEXT,
    evidence_value   TEXT,
    source_system    VARCHAR(80),
    source_reference TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bom_evidence_component
    ON tenant_default.bom_component_evidence (bom_component_id, evidence_type);
CREATE INDEX IF NOT EXISTS idx_bom_evidence_bom
    ON tenant_default.bom_component_evidence (bom_id);

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_vulnerability_links (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id          UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    bom_id                    UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    vulnerability_key         VARCHAR(128) NOT NULL,
    vulnerability_source      VARCHAR(40) NOT NULL DEFAULT 'NVD',
    relation_type             VARCHAR(40) NOT NULL DEFAULT 'CVE',
    match_source              VARCHAR(80),
    match_confidence          NUMERIC(5,2),
    direct_match              BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_evidence_json JSONB,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_component
    ON tenant_default.bom_component_vulnerability_links (bom_component_id, vulnerability_key);
CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_bom
    ON tenant_default.bom_component_vulnerability_links (bom_id);
CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_source
    ON tenant_default.bom_component_vulnerability_links (tenant_id, vulnerability_source, relation_type);

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_workflows (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id      UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    vulnerability_link_id UUID REFERENCES tenant_default.bom_component_vulnerability_links(id) ON DELETE CASCADE,
    workflow_type         VARCHAR(40) NOT NULL DEFAULT 'INVESTIGATION',
    workflow_status       VARCHAR(40) NOT NULL DEFAULT 'DISCOVERED',
    workflow_reason       TEXT,
    investigation_key     VARCHAR(128),
    finding_id            UUID,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at             TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_bom_workflow_component
    ON tenant_default.bom_component_workflows (bom_component_id, workflow_status);
CREATE INDEX IF NOT EXISTS idx_bom_workflow_link
    ON tenant_default.bom_component_workflows (vulnerability_link_id);
