-- Missing or incomplete provider evidence is an explicit UNKNOWN state, never a safe default.
ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_scan_status_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_scan_status_check
    CHECK (pii_scan_status IN ('UNKNOWN','NOT_APPLICABLE','NOT_SCANNED','SCANNED_CLEAN','SCANNED_PII_FOUND','LOOKUP_FAILED'));

UPDATE ai_security_artifacts
   SET pii_scan_status = 'UNKNOWN'
 WHERE artifact_type IN ('KNOWLEDGE_BASE','DATA_SOURCE','DATA_STORE','SEARCH_INDEX')
   AND pii_scan_status = 'NOT_APPLICABLE';
