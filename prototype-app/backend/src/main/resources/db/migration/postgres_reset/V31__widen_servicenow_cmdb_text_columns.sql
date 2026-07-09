-- Widen servicenow_cmdb_configs columns that were too narrow (varchar 255)
-- to match the entity declarations (install_fields/discovery_fields/queries -> 4000,
-- last_test_message -> 2000) across every tenant schema.
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'servicenow_cmdb_configs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.servicenow_cmdb_configs
                    ALTER COLUMN install_fields TYPE varchar(4000),
                    ALTER COLUMN install_query TYPE varchar(4000),
                    ALTER COLUMN discovery_fields TYPE varchar(4000),
                    ALTER COLUMN discovery_query TYPE varchar(4000),
                    ALTER COLUMN last_test_message TYPE varchar(2000)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
