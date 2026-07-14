-- migration-guard: platform-only
CREATE TABLE IF NOT EXISTS platform.tenant_schema_versions (
    tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id) ON DELETE CASCADE,
    schema_name varchar(120) NOT NULL UNIQUE,
    current_version integer NOT NULL DEFAULT 0,
    target_version integer NOT NULL DEFAULT 42,
    status varchar(24) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'MIGRATING', 'CURRENT', 'FAILED', 'DRIFTED', 'PROVISIONING_FAILED')),
    structural_checksum varchar(64),
    migration_started_at timestamptz,
    migration_completed_at timestamptz,
    last_successful_version integer NOT NULL DEFAULT 0,
    failure_code varchar(80),
    failure_message varchar(1000),
    updated_at timestamptz NOT NULL DEFAULT now(),
    migration_run_id uuid
);

CREATE INDEX IF NOT EXISTS idx_tenant_schema_versions_status
    ON platform.tenant_schema_versions(status, current_version);

COMMENT ON TABLE platform.tenant_schema_versions IS
    'Operational projection of per-schema tenant_schema_history. Flyway history remains authoritative.';
