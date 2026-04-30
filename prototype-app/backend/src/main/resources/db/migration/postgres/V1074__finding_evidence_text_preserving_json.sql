DROP INDEX IF EXISTS idx_findings_evidence_gin;
DROP INDEX IF EXISTS idx_finding_events_details_gin;

ALTER TABLE IF EXISTS findings
    ALTER COLUMN evidence TYPE text
        USING CASE WHEN evidence IS NULL THEN NULL
                   ELSE evidence::text END;

ALTER TABLE IF EXISTS finding_events
    ALTER COLUMN details_json TYPE text
        USING CASE WHEN details_json IS NULL THEN NULL
                   ELSE details_json::text END;
