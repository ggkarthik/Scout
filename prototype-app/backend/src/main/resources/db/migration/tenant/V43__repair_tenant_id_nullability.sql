-- Repair tenant_id columns that existed before V42 and therefore retained
-- their legacy nullable definition and weaker policy predicate.
DO $tenant_rls_repair$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    table_record record;
    conflict_count bigint;
    predicate text;
BEGIN
    IF current_schema() <> target_schema THEN
        RAISE EXCEPTION 'Tenant migration search_path mismatch: expected %, got %', target_schema, current_schema();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM platform.tenants
        WHERE id = target_tenant AND schema_name = target_schema
    ) THEN
        RAISE EXCEPTION 'Tenant/schema registration mismatch for %', target_schema;
    END IF;

    FOR table_record IN
        SELECT c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = target_schema
          AND c.relkind IN ('r', 'p')
          AND c.relname NOT IN ('tenant_schema_history', 'flyway_schema_history')
        ORDER BY c.relname
    LOOP
        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE tenant_id IS NOT NULL AND tenant_id <> $1',
            target_schema, table_record.table_name
        ) INTO conflict_count USING target_tenant;
        IF conflict_count > 0 THEN
            RAISE EXCEPTION 'Conflicting tenant_id values in %.% (% rows)',
                target_schema, table_record.table_name, conflict_count;
        END IF;

        EXECUTE format(
            'UPDATE %I.%I SET tenant_id = $1 WHERE tenant_id IS NULL',
            target_schema, table_record.table_name
        ) USING target_tenant;
        EXECUTE format(
            'ALTER TABLE %I.%I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
            target_schema, table_record.table_name, target_tenant::text
        );
        EXECUTE format(
            'ALTER TABLE %I.%I ALTER COLUMN tenant_id SET NOT NULL',
            target_schema, table_record.table_name
        );

        predicate := format(
            'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid'
            ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid',
            target_tenant::text
        );
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', target_schema, table_record.table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I.%I USING (%s) WITH CHECK (%s)',
            target_schema, table_record.table_name, predicate, predicate
        );
    END LOOP;
END
$tenant_rls_repair$;
