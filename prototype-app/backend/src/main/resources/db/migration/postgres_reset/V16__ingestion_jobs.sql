CREATE TABLE IF NOT EXISTS tenant_default.ingestion_jobs (
    id uuid PRIMARY KEY,
    job_type varchar(80) NOT NULL,
    source_type varchar(80) NOT NULL,
    asset_identifier varchar(500) NOT NULL,
    status varchar(32) NOT NULL,
    requested_by varchar(255),
    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    dedupe_key varchar(700) NOT NULL,
    payload_json text,
    result_json text,
    failure_code varchar(120),
    failure_message text,
    visible_at timestamptz NOT NULL DEFAULT now(),
    sbom_upload_id uuid,
    tenant_id uuid NOT NULL,
    CONSTRAINT ingestion_jobs_status_check CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    CONSTRAINT fk_ingestion_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_ingestion_jobs_sbom_upload FOREIGN KEY (sbom_upload_id) REFERENCES tenant_default.sbom_uploads (id)
);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_status_visible
    ON tenant_default.ingestion_jobs (status, visible_at, id);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_requested_desc
    ON tenant_default.ingestion_jobs (requested_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_asset_status
    ON tenant_default.ingestion_jobs (asset_identifier, status);

CREATE UNIQUE INDEX IF NOT EXISTS uk_ingestion_jobs_dedupe_active
    ON tenant_default.ingestion_jobs (dedupe_key)
    WHERE status IN ('QUEUED', 'RUNNING');
