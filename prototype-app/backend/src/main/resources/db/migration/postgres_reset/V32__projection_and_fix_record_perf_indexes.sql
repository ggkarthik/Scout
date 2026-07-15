DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'finding_list_projection'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_finding_list_projection_rank_cursor
                    ON %I.finding_list_projection (
                        risk_score DESC,
                        coalesce(due_at, %L::timestamptz) ASC,
                        updated_at DESC,
                        finding_id ASC
                    )',
                target_schema.table_schema,
                '9999-12-31T00:00:00Z'
        );
    END LOOP;

    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'fix_records'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_fix_records_patchable_upper_cve
                    ON %I.fix_records (upper(cve_id))
                    WHERE upper(fix_type) <> %L',
                target_schema.table_schema,
                'NO_FIX'
        );
    END LOOP;
END
$$;
