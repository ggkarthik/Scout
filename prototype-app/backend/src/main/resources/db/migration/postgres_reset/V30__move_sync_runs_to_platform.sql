CREATE TABLE IF NOT EXISTS platform.sync_runs (
    id uuid PRIMARY KEY,
    completed_at timestamptz,
    error_message varchar(2000),
    metadata_json text,
    records_failed integer NOT NULL DEFAULT 0,
    records_fetched integer NOT NULL DEFAULT 0,
    records_inserted integer NOT NULL DEFAULT 0,
    records_updated integer NOT NULL DEFAULT 0,
    run_scope varchar(64) NOT NULL DEFAULT 'PLATFORM_VULNERABILITY',
    started_at timestamptz NOT NULL,
    status varchar(255) NOT NULL,
    sync_type varchar(255) NOT NULL,
    tenant_id uuid,
    CONSTRAINT fk_sync_runs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

DO $$
DECLARE
    source_schema record;
BEGIN
    FOR source_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'sync_runs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format($sql$
            INSERT INTO platform.sync_runs (
                id,
                completed_at,
                error_message,
                metadata_json,
                records_failed,
                records_fetched,
                records_inserted,
                records_updated,
                run_scope,
                started_at,
                status,
                sync_type,
                tenant_id
            )
            SELECT
                id,
                completed_at,
                error_message,
                metadata_json,
                COALESCE(records_failed, 0),
                records_fetched,
                records_inserted,
                records_updated,
                run_scope,
                started_at,
                status,
                sync_type,
                tenant_id
            FROM %I.sync_runs
            ON CONFLICT (id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                error_message = EXCLUDED.error_message,
                metadata_json = EXCLUDED.metadata_json,
                records_failed = EXCLUDED.records_failed,
                records_fetched = EXCLUDED.records_fetched,
                records_inserted = EXCLUDED.records_inserted,
                records_updated = EXCLUDED.records_updated,
                run_scope = EXCLUDED.run_scope,
                started_at = EXCLUDED.started_at,
                status = EXCLUDED.status,
                sync_type = EXCLUDED.sync_type,
                tenant_id = EXCLUDED.tenant_id
            $sql$, source_schema.table_schema);
    END LOOP;

    FOR source_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'sync_runs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I.sync_runs CASCADE', source_schema.table_schema);
    END LOOP;
END
$$;

CREATE INDEX IF NOT EXISTS idx_sync_runs_run_scope_started
    ON platform.sync_runs (run_scope, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant_started
    ON platform.sync_runs (tenant_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_sync_type_status
    ON platform.sync_runs (lower(sync_type), lower(status), started_at DESC);
