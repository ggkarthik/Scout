DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name IN ('findings', 'org_cve_records')
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_findings_tenant_status_component
                    ON %I.findings (tenant_id, status, component_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_created_at
                    ON %I.org_cve_records (tenant_id, created_at DESC)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_upper_severity
                    ON %I.org_cve_records (tenant_id, upper(coalesce(severity, %L)))',
                target_schema.table_schema,
                'UNKNOWN'
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_exposure_browse
                    ON %I.org_cve_records (
                        tenant_id,
                        applicability_state,
                        matched_asset_count,
                        impacted,
                        in_kev,
                        epss_score DESC,
                        cvss_score DESC,
                        external_id
                    )',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
