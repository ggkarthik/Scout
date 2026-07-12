DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'azure_discovery_configs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.azure_discovery_targets (
                    id UUID PRIMARY KEY,
                    tenant_id UUID NOT NULL,
                    config_id UUID NOT NULL,
                    subscription_id VARCHAR(64),
                    subscription_name VARCHAR(255),
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    regions_json TEXT NOT NULL DEFAULT ''["eastus2"]'',
                    last_test_status VARCHAR(64),
                    last_test_message VARCHAR(2000),
                    last_tested_at TIMESTAMPTZ,
                    last_sync_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    CONSTRAINT fk_azure_discovery_targets_config FOREIGN KEY (config_id) REFERENCES %I.azure_discovery_configs (id),
                    CONSTRAINT fk_azure_discovery_targets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT uk_azure_discovery_targets_config_subscription UNIQUE (config_id, subscription_id)
                )',
                target_schema.table_schema,
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_targets_config
                    ON %I.azure_discovery_targets (config_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_targets_tenant_enabled
                    ON %I.azure_discovery_targets (tenant_id, enabled)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
