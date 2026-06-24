DO $$
DECLARE
    table_record record;
BEGIN
    FOR table_record IN
        SELECT c.table_schema, c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
        WHERE c.column_name = 'tenant_id'
          AND c.is_nullable = 'NO'
          AND t.table_type = 'BASE TABLE'
          AND (
                c.table_schema LIKE 'tenant\_%' ESCAPE '\'
                OR (c.table_schema = 'platform' AND c.table_name IN ('personal_finding_queues', 'finding_queue_preferences'))
          )
        ORDER BY c.table_schema, c.table_name
    LOOP
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', table_record.table_schema, table_record.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', table_record.table_schema, table_record.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', table_record.table_schema, table_record.table_name);
        EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I.%I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
                table_record.table_schema,
                table_record.table_name
        );
    END LOOP;
END
$$;
