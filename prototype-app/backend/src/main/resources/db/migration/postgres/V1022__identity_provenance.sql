-- BLG-015: Canonical identity graph with provenance.
--
-- Adds provenance tracking fields to the identity graph so auditors and
-- downstream consumers can understand where each identifier and link came from,
-- how it was established, and what confidence level it carries.
--
-- software_identifiers: track which ingestion pass introduced the identifier and
--   include a free-text provenance note (e.g. "matched via CSAF advisory").
--
-- identity_links: track when the link was verified, by which process/user, and a
--   provenance note explaining the evidence for the cross-source link.

ALTER TABLE IF EXISTS software_identifiers
    ADD COLUMN IF NOT EXISTS provenance_note VARCHAR(500);

ALTER TABLE IF EXISTS identity_links
    ADD COLUMN IF NOT EXISTS verified_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verified_by    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS provenance_note VARCHAR(500);

-- Index to quickly find all links verified by a specific process.
CREATE INDEX IF NOT EXISTS idx_identity_links_verified_by
    ON identity_links (verified_by)
    WHERE verified_by IS NOT NULL;
