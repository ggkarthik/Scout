DO $$
DECLARE
    target_schema text;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'demo_requests'
          AND (table_schema = 'tenant_default' OR table_schema LIKE 'tenant\_%' ESCAPE '\')
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.demo_requests ADD COLUMN IF NOT EXISTS bootstrap_status varchar(64)',
                target_schema);
    END LOOP;
END $$;
