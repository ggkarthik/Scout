DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'assets'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.azure_discovery_configs (
                    id UUID PRIMARY KEY,
                    tenant_id UUID NOT NULL,
                    source_system VARCHAR(80) NOT NULL DEFAULT ''azure'',
                    auth_type VARCHAR(32) NOT NULL DEFAULT ''CLIENT_SECRET'',
                    azure_tenant_id VARCHAR(128),
                    client_id VARCHAR(255),
                    client_secret TEXT,
                    subscription_ids_json TEXT NOT NULL DEFAULT ''[]'',
                    regions_json TEXT NOT NULL DEFAULT ''["eastus2"]'',
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    auto_sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    interval_minutes INTEGER NOT NULL DEFAULT 1440,
                    last_test_status VARCHAR(64),
                    last_test_message VARCHAR(2000),
                    last_tested_at TIMESTAMPTZ,
                    last_sync_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    CONSTRAINT fk_azure_discovery_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT uk_azure_discovery_configs_tenant_source UNIQUE (tenant_id, source_system),
                    CONSTRAINT azure_discovery_configs_auth_type_check CHECK (auth_type IN (''CLIENT_SECRET'', ''MANAGED_IDENTITY''))
                )',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_configs_enabled
                    ON %I.azure_discovery_configs (enabled, auto_sync_enabled)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_configs_tenant
                    ON %I.azure_discovery_configs (tenant_id)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
