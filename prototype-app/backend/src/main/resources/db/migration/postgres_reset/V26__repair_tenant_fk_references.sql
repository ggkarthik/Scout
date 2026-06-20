-- Repair foreign-key constraints in non-default tenant schemas that were copied verbatim
-- from tenant_default by an earlier provisionTenantSchema implementation. Those FKs
-- reference tenant_default.<table> instead of <own_schema>.<table>, so any insert into the
-- affected tenant's table that depended on within-tenant referential integrity (e.g.
-- cis.asset_id -> assets.id) failed with a foreign-key violation.
--
-- This migration finds every such cross-schema FK pointing at tenant_default from a
-- tenant_<name> schema, drops it, and recreates it pointing at the FK's own schema.
-- Only FKs whose referenced table also exists in the local schema are rewritten so we
-- never silently drop a constraint we cannot replace.

DO $$
DECLARE
    rec RECORD;
    new_def TEXT;
BEGIN
    FOR rec IN
        SELECT
            n.nspname    AS schema_name,
            cl.relname   AS table_name,
            con.conname  AS constraint_name,
            pg_get_constraintdef(con.oid) AS definition,
            confcl.relname AS referenced_table
        FROM pg_constraint con
        JOIN pg_class cl     ON cl.oid = con.conrelid
        JOIN pg_namespace n  ON n.oid = cl.relnamespace
        JOIN pg_class confcl ON confcl.oid = con.confrelid
        JOIN pg_namespace confn ON confn.oid = confcl.relnamespace
        WHERE con.contype = 'f'
          AND n.nspname LIKE 'tenant\_%' ESCAPE '\'
          AND n.nspname <> 'tenant_default'
          AND confn.nspname = 'tenant_default'
          AND EXISTS (
              SELECT 1 FROM pg_tables t
              WHERE t.schemaname = n.nspname
                AND t.tablename  = confcl.relname
          )
    LOOP
        new_def := replace(
            rec.definition,
            'REFERENCES tenant_default.',
            'REFERENCES ' || quote_ident(rec.schema_name) || '.'
        );
        EXECUTE format(
            'ALTER TABLE %I.%I DROP CONSTRAINT %I',
            rec.schema_name, rec.table_name, rec.constraint_name
        );
        EXECUTE format(
            'ALTER TABLE %I.%I ADD CONSTRAINT %I %s',
            rec.schema_name, rec.table_name, rec.constraint_name, new_def
        );
    END LOOP;
END
$$;
