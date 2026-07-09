DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name IN ('inventory_components', 'component_vulnerability_states')
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_inventory_tenant_software_identity
                    ON %I.inventory_components (tenant_id, software_identity_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_vulnerability_component
                    ON %I.component_vulnerability_states (tenant_id, vulnerability_id, component_id)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
