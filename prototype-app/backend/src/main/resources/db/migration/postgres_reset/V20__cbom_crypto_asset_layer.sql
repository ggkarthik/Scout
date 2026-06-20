CREATE TABLE IF NOT EXISTS tenant_default.cbom_components (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    asset_id              UUID REFERENCES tenant_default.assets(id),
    source_bom_id         UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    bom_ref               TEXT,
    component_fingerprint TEXT NOT NULL,
    name                  TEXT NOT NULL,
    description           TEXT,
    asset_type            VARCHAR(60) NOT NULL,
    component_type        TEXT,
    primitive             TEXT,
    parameter_set_identifier TEXT,
    key_size              INTEGER,
    curve                 TEXT,
    padding               TEXT,
    protocol_version      TEXT,
    state                 TEXT,
    format                TEXT,
    storage_location      TEXT,
    transmission          TEXT,
    sensitivity           TEXT,
    used_in               TEXT,
    not_before            DATE,
    not_after             DATE,
    issuer                TEXT,
    subject               TEXT,
    serial_number         TEXT,
    signature_algorithm   TEXT,
    key_usage             TEXT,
    risk_score            NUMERIC(4,2),
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_bom_id, component_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_cbom_components_tenant_asset
    ON tenant_default.cbom_components (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_cbom_components_source_bom
    ON tenant_default.cbom_components (source_bom_id);
CREATE INDEX IF NOT EXISTS idx_cbom_components_bom_ref
    ON tenant_default.cbom_components (tenant_id, asset_id, bom_ref)
    WHERE bom_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cbom_components_asset_type
    ON tenant_default.cbom_components (tenant_id, asset_type);

CREATE TABLE IF NOT EXISTS tenant_default.cbom_risk_findings (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    cbom_component_id     UUID NOT NULL REFERENCES tenant_default.cbom_components(id) ON DELETE CASCADE,
    rule_id               VARCHAR(100) NOT NULL,
    rule_version          VARCHAR(20) NOT NULL DEFAULT '1',
    finding_fingerprint   TEXT NOT NULL,
    risk_class            VARCHAR(80) NOT NULL,
    severity              VARCHAR(20) NOT NULL,
    title                 TEXT NOT NULL,
    detail                TEXT,
    evidence              JSONB,
    recommendation        TEXT,
    status                VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cbom_component_id, finding_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_cbom_risk_findings_component
    ON tenant_default.cbom_risk_findings (cbom_component_id);
CREATE INDEX IF NOT EXISTS idx_cbom_risk_findings_tenant_status
    ON tenant_default.cbom_risk_findings (tenant_id, status, severity);

CREATE TABLE IF NOT EXISTS tenant_default.cbom_posture_summary (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    asset_id              UUID NOT NULL REFERENCES tenant_default.assets(id),
    last_source_bom_id    UUID REFERENCES tenant_default.bom_ingestion_records(id),
    total_components      INTEGER NOT NULL DEFAULT 0,
    critical_findings     INTEGER NOT NULL DEFAULT 0,
    high_findings         INTEGER NOT NULL DEFAULT 0,
    medium_findings       INTEGER NOT NULL DEFAULT 0,
    low_findings          INTEGER NOT NULL DEFAULT 0,
    info_findings         INTEGER NOT NULL DEFAULT 0,
    accepted_findings     INTEGER NOT NULL DEFAULT 0,
    quantum_vulnerable    INTEGER NOT NULL DEFAULT 0,
    weak_algorithms       INTEGER NOT NULL DEFAULT 0,
    expiring_certs        INTEGER NOT NULL DEFAULT 0,
    posture_score         NUMERIC(4,2),
    last_evaluated_at     TIMESTAMPTZ,
    UNIQUE (tenant_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cbom_posture_summary_tenant
    ON tenant_default.cbom_posture_summary (tenant_id);
