-- Postgres-safe incremental adoption migration for org-CVE read paths.

DO $$
BEGIN
  IF to_regclass('org_cve_records') IS NULL THEN
    RETURN;
  END IF;

  UPDATE org_cve_records
  SET external_id = UPPER(external_id)
  WHERE external_id IS NOT NULL
    AND external_id <> UPPER(external_id);

  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_external_id ON org_cve_records(tenant_id, external_id)';
  EXECUTE 'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_rank ON org_cve_records(tenant_id, impacted, applicability_state, cvss_score, external_id)';
END $$;
