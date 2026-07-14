-- Executed once per tenant schema by TenantSchemaMigrationService.
-- ${tenantId} and ${tenantSchema} are validated values supplied by the control plane.
DO $tenant_rls$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    table_record record;
    has_tenant_id boolean;
    tenant_id_nullable boolean;
    conflict_count bigint;
    has_tenant_fk boolean;
    tenant_fk_name text;
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
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = target_schema
              AND table_name = table_record.table_name
              AND column_name = 'tenant_id'
        ) INTO has_tenant_id;

        IF NOT has_tenant_id THEN
            EXECUTE format('ALTER TABLE %I.%I ADD COLUMN tenant_id uuid', target_schema, table_record.table_name);
            EXECUTE format('UPDATE %I.%I SET tenant_id = $1 WHERE tenant_id IS NULL', target_schema, table_record.table_name)
                USING target_tenant;
            EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                           target_schema, table_record.table_name, target_tenant::text);
            EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN tenant_id SET NOT NULL', target_schema, table_record.table_name);
            has_tenant_id := true;
        END IF;

        EXECUTE format('SELECT count(*) FROM %I.%I WHERE tenant_id IS NOT NULL AND tenant_id <> $1',
                       target_schema, table_record.table_name)
            INTO conflict_count USING target_tenant;
        IF conflict_count > 0 THEN
            RAISE EXCEPTION 'Conflicting tenant_id values in %.% (% rows)',
                target_schema, table_record.table_name, conflict_count;
        END IF;

        SELECT EXISTS (
            SELECT 1
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_namespace n ON n.oid = rel.relnamespace
            JOIN pg_class referenced ON referenced.oid = con.confrelid
            JOIN pg_namespace referenced_ns ON referenced_ns.oid = referenced.relnamespace
            WHERE n.nspname = target_schema
              AND rel.relname = table_record.table_name
              AND con.contype = 'f'
              AND referenced_ns.nspname = 'platform'
              AND referenced.relname = 'tenants'
              AND pg_get_constraintdef(con.oid) LIKE 'FOREIGN KEY (tenant_id)%'
        ) INTO has_tenant_fk;
        IF NOT has_tenant_fk THEN
            tenant_fk_name := left(table_record.table_name || '_tenant_id_fkey', 63);
            EXECUTE format(
                'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) NOT VALID',
                target_schema, table_record.table_name, tenant_fk_name
            );
            EXECUTE format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I',
                           target_schema, table_record.table_name, tenant_fk_name);
        END IF;

        SELECT is_nullable = 'YES'
          INTO tenant_id_nullable
          FROM information_schema.columns
         WHERE table_schema = target_schema
           AND table_name = table_record.table_name
           AND column_name = 'tenant_id';

        predicate := format(
            'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid',
            target_tenant::text
        );
        IF NOT tenant_id_nullable THEN
            predicate := predicate ||
                ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid';
        END IF;

        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', target_schema, table_record.table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I.%I USING (%s) WITH CHECK (%s)',
                       target_schema, table_record.table_name, predicate, predicate);
    END LOOP;
END
$tenant_rls$;
