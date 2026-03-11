-- BLG-008: Add composite indexes that were missing from the baseline schema.
--
-- investigations has no indexes beyond the PK, despite being queried by
-- (tenant_id, vulnerability_id) in the CVE detail workbench and by
-- (tenant_id, status) in the investigation management views.
--
-- applicability_assessments is queried by (tenant_id, vulnerability_id) but only
-- has individual column indexes, causing sequential scans at scale.
--
-- findings lacks a (tenant_id, decision_state) composite which is needed for the
-- "filter by decision state" path in FindingsPage — currently falling back to
-- a heap scan filtered post-retrieval.

-- investigations: primary query patterns
CREATE INDEX IF NOT EXISTS idx_investigations_tenant_vuln
    ON investigations (tenant_id, vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_investigations_tenant_status_created
    ON investigations (tenant_id, status, created_at DESC);

-- applicability_assessments: CVE detail page lookup
CREATE INDEX IF NOT EXISTS idx_applicability_assessments_tenant_vuln
    ON applicability_assessments (tenant_id, vulnerability_id);

-- findings: decision state filter
CREATE INDEX IF NOT EXISTS idx_findings_tenant_decision_state
    ON findings (tenant_id, decision_state);

-- findings: combined decision state + workflow status (most common filter combination)
CREATE INDEX IF NOT EXISTS idx_findings_tenant_decision_status
    ON findings (tenant_id, decision_state, status);
