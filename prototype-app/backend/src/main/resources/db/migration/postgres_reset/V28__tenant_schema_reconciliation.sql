DO $$
DECLARE
    target_schema record;
    source_table record;
    source_column record;
BEGIN
    FOR target_schema IN
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name LIKE 'tenant\_%' ESCAPE '\'
          AND schema_name <> 'tenant_default'
    LOOP
        FOR source_table IN
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'tenant_default'
              AND tablename <> 'flyway_schema_history'
            ORDER BY tablename
        LOOP
            EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I.%I (LIKE tenant_default.%I INCLUDING CONSTRAINTS INCLUDING GENERATED INCLUDING IDENTITY INCLUDING INDEXES INCLUDING STORAGE INCLUDING COMMENTS)',
                    target_schema.schema_name,
                    source_table.tablename,
                    source_table.tablename
            );
        END LOOP;

        FOR source_column IN
            SELECT c.table_name,
                   c.column_name,
                   c.data_type,
                   c.udt_name,
                   c.character_maximum_length,
                   c.numeric_precision,
                   c.numeric_scale,
                   c.datetime_precision,
                   c.column_default
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON t.table_schema = c.table_schema
             AND t.table_name = c.table_name
            WHERE c.table_schema = 'tenant_default'
              AND t.table_type = 'BASE TABLE'
              AND c.table_name <> 'flyway_schema_history'
              AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns existing
                    WHERE existing.table_schema = target_schema.schema_name
                      AND existing.table_name = c.table_name
                      AND existing.column_name = c.column_name
              )
            ORDER BY c.table_name, c.ordinal_position
        LOOP
            EXECUTE format(
                    'ALTER TABLE %I.%I ADD COLUMN IF NOT EXISTS %I %s%s',
                    target_schema.schema_name,
                    source_column.table_name,
                    source_column.column_name,
                    CASE
                        WHEN source_column.data_type = 'USER-DEFINED' THEN source_column.udt_name
                        WHEN source_column.data_type IN ('character varying', 'character')
                            THEN source_column.data_type || COALESCE('(' || source_column.character_maximum_length || ')', '')
                        WHEN source_column.data_type = 'numeric' AND source_column.numeric_precision IS NOT NULL
                            THEN source_column.data_type || '(' || source_column.numeric_precision || COALESCE(',' || source_column.numeric_scale, '') || ')'
                        WHEN source_column.data_type LIKE 'timestamp%'
                            THEN source_column.data_type
                        ELSE source_column.data_type
                    END,
                    CASE
                        WHEN source_column.column_default IS NULL THEN ''
                        ELSE ' DEFAULT ' || replace(source_column.column_default, 'tenant_default.', format('%I.', target_schema.schema_name))
                    END
            );
        END LOOP;
    END LOOP;
END
$$;
