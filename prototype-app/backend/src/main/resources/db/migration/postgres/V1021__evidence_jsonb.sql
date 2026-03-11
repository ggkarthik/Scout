-- BLG-012: Queryable audit evidence.
--
-- Converts the evidence and details_json columns from opaque TEXT to proper JSONB.
-- This allows:
--   - Structural queries and filtering on evidence fields (e.g. WHERE evidence->>'matchedBy' = 'purl')
--   - GIN-indexed containment checks (e.g. WHERE evidence @> '{"decisionState":"AFFECTED"}')
--   - Schema validation at the DB layer (invalid JSON will fail the cast)
--
-- The USING clause handles the cast for all existing rows.
-- NULL rows pass through unchanged. An empty-string value would fail the cast, but
-- FindingEvidenceService always produces valid JSON, so this is safe.

ALTER TABLE IF EXISTS findings
    ALTER COLUMN evidence TYPE jsonb
        USING CASE WHEN evidence IS NULL OR trim(evidence) = '' THEN NULL
                   ELSE evidence::jsonb END;

ALTER TABLE IF EXISTS finding_events
    ALTER COLUMN details_json TYPE jsonb
        USING CASE WHEN details_json IS NULL OR trim(details_json) = '' THEN NULL
                   ELSE details_json::jsonb END;

-- GIN indexes enable @> containment searches and jsonb_path_query_array expressions.
CREATE INDEX IF NOT EXISTS idx_findings_evidence_gin
    ON findings USING gin(evidence)
    WHERE evidence IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finding_events_details_gin
    ON finding_events USING gin(details_json)
    WHERE details_json IS NOT NULL;
