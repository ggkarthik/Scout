DO $$
DECLARE
    schema_record record;
BEGIN
    FOR schema_record IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'github_sbom_sources'
          AND table_schema NOT IN ('information_schema', 'pg_catalog')
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.github_sbom_sources ADD COLUMN IF NOT EXISTS github_token TEXT',
                schema_record.table_schema
        );
    END LOOP;
END
$$;
