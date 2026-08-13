-- Per-artifact PII classification summary, sourced read-only from AWS Macie / Azure Purview
-- against storage the artifact is already known to read from (READS_FROM_S3 /
-- READS_FROM_STORAGE_ACCOUNT relationships). Scout never scans content itself.

ALTER TABLE ai_security_artifacts
    ADD COLUMN IF NOT EXISTS pii_scan_status varchar(32) NOT NULL DEFAULT 'NOT_APPLICABLE',
    ADD COLUMN IF NOT EXISTS pii_source varchar(32),
    ADD COLUMN IF NOT EXISTS pii_info_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS pii_finding_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pii_last_scanned_at timestamptz;

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_scan_status_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_scan_status_check
    CHECK (pii_scan_status IN ('NOT_APPLICABLE','NOT_SCANNED','SCANNED_CLEAN','SCANNED_PII_FOUND','LOOKUP_FAILED'));

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_source_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_source_check
    CHECK (pii_source IS NULL OR pii_source IN ('AWS_MACIE','AZURE_PURVIEW'));

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_finding_count_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_finding_count_check
    CHECK (pii_finding_count >= 0);
