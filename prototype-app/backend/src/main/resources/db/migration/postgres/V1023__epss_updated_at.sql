-- BLG-016: EPSS integration.
--
-- Adds an epss_updated_at timestamp to vulnerabilities so the daily EPSS
-- refresh job can identify rows whose scores are stale (never refreshed, or
-- refreshed before the current FIRST.org publication date).
--
-- The epss_score column already exists (added in the core schema baseline).
-- This migration only adds the freshness tracking column.

ALTER TABLE IF EXISTS vulnerabilities
    ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ;

-- Index so EpssRefreshService can efficiently query stale rows.
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss_updated_at
    ON vulnerabilities (epss_updated_at NULLS FIRST);
