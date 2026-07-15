\set ON_ERROR_STOP on

DO $migration_preflight$
DECLARE
    tenant_record record;
    table_record record;
    history_version integer;
    failed_migrations integer;
    conflict_count bigint;
BEGIN
    IF to_regclass('public.flyway_schema_history') IS NULL THEN
        RAISE EXCEPTION 'Platform Flyway history is missing';
    END IF;

    SELECT COALESCE(max(version::integer), 0),
           count(*) FILTER (WHERE NOT success)
      INTO history_version, failed_migrations
      FROM public.flyway_schema_history
     WHERE version ~ '^[0-9]+$';

    IF history_version < 44 OR failed_migrations > 0 THEN
        RAISE EXCEPTION 'Platform migration state is unsafe (version %, failed rows %)',
            history_version, failed_migrations;
    END IF;

    FOR tenant_record IN
        SELECT t.id, t.schema_name
          FROM platform.tenants t
         WHERE t.deleted_at IS NULL
           AND upper(t.status) NOT IN ('DELETED', 'PURGED')
         ORDER BY t.schema_name
    LOOP
        IF to_regnamespace(tenant_record.schema_name) IS NULL THEN
            RAISE EXCEPTION 'Registered tenant schema % is missing', tenant_record.schema_name;
        END IF;

        IF to_regclass(format('%I.tenant_schema_history', tenant_record.schema_name)) IS NULL THEN
            RAISE EXCEPTION 'Tenant Flyway history is missing for %', tenant_record.schema_name;
        END IF;

        EXECUTE format(
            'SELECT COALESCE(max(version::integer), 0), count(*) FILTER (WHERE NOT success) '
            'FROM %I.tenant_schema_history WHERE version ~ ''^[0-9]+$''',
            tenant_record.schema_name
        ) INTO history_version, failed_migrations;

        IF history_version < 44 OR failed_migrations > 0 THEN
            RAISE EXCEPTION 'Tenant migration state is unsafe for % (version %, failed rows %)',
                tenant_record.schema_name, history_version, failed_migrations;
        END IF;

        IF NOT EXISTS (
            SELECT 1
              FROM platform.tenant_schema_versions v
             WHERE v.tenant_id = tenant_record.id
               AND v.schema_name = tenant_record.schema_name
               AND v.status = 'CURRENT'
               AND v.current_version >= 44
               AND v.target_version >= 44
               AND v.last_successful_version >= 44
               AND nullif(btrim(v.structural_checksum), '') IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'Control-plane migration state is not current for %', tenant_record.schema_name;
        END IF;

        FOR table_record IN
            SELECT c.oid AS table_oid, c.relname AS table_name,
                   c.relrowsecurity, c.relforcerowsecurity
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = tenant_record.schema_name
               AND c.relkind IN ('r', 'p')
               AND c.relname NOT IN ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
             ORDER BY c.relname
        LOOP
            IF NOT table_record.relrowsecurity OR NOT table_record.relforcerowsecurity THEN
                RAISE EXCEPTION 'RLS is not enabled and forced on %.%',
                    tenant_record.schema_name, table_record.table_name;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_policy
                 WHERE polrelid = table_record.table_oid
                   AND polname = 'tenant_isolation'
            ) THEN
                RAISE EXCEPTION 'tenant_isolation policy is missing on %.%',
                    tenant_record.schema_name, table_record.table_name;
            END IF;

            -- audit_events intentionally permits null-tenant platform/pre-auth events.
            -- Tenant-attributed rows must still match the schema registration.
            IF table_record.table_name = 'audit_events' THEN
                EXECUTE format(
                    'SELECT count(*) FROM %I.%I WHERE tenant_id IS NOT NULL AND tenant_id <> $1',
                    tenant_record.schema_name, table_record.table_name
                ) INTO conflict_count USING tenant_record.id;
                IF conflict_count > 0 THEN
                    RAISE EXCEPTION 'Conflicting tenant rows in %.% (% rows)',
                        tenant_record.schema_name, table_record.table_name, conflict_count;
                END IF;
                CONTINUE;
            END IF;

            IF NOT EXISTS (
                SELECT 1
                  FROM pg_attribute
                 WHERE attrelid = table_record.table_oid
                   AND attname = 'tenant_id'
                   AND attnum > 0
                   AND NOT attisdropped
                   AND attnotnull
            ) THEN
                RAISE EXCEPTION 'A non-null tenant_id is missing on %.%',
                    tenant_record.schema_name, table_record.table_name;
            END IF;

            IF NOT EXISTS (
                SELECT 1
                  FROM pg_constraint con
                  JOIN pg_class referenced ON referenced.oid = con.confrelid
                  JOIN pg_namespace referenced_ns ON referenced_ns.oid = referenced.relnamespace
                 WHERE con.conrelid = table_record.table_oid
                   AND con.contype = 'f'
                   AND con.convalidated
                   AND referenced_ns.nspname = 'platform'
                   AND referenced.relname = 'tenants'
                   AND pg_get_constraintdef(con.oid) LIKE 'FOREIGN KEY (tenant_id)%'
            ) THEN
                RAISE EXCEPTION 'Validated platform tenant foreign key is missing on %.%',
                    tenant_record.schema_name, table_record.table_name;
            END IF;

            EXECUTE format(
                'SELECT count(*) FROM %I.%I WHERE tenant_id IS DISTINCT FROM $1',
                tenant_record.schema_name, table_record.table_name
            ) INTO conflict_count USING tenant_record.id;

            IF conflict_count > 0 THEN
                RAISE EXCEPTION 'Conflicting tenant rows in %.% (% rows)',
                    tenant_record.schema_name, table_record.table_name, conflict_count;
            END IF;
        END LOOP;
    END LOOP;
END
$migration_preflight$;

SELECT 'migration_preflight_status=verified';
