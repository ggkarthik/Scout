-- V1085: Fix records — generated remediation guidance per CVE per tenant
CREATE TABLE fix_records (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL REFERENCES tenants(id),
    cve_id                TEXT        NOT NULL,
    related_cve_ids       TEXT[],
    summary               TEXT        NOT NULL,
    description           TEXT,
    fix_type              TEXT        NOT NULL,
    software_entities     JSONB,
    os_hint               TEXT,
    recommendation_source TEXT        NOT NULL,
    source_urls           TEXT[],
    generated_at          TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_fix_records_tenant_cve ON fix_records (tenant_id, cve_id);
