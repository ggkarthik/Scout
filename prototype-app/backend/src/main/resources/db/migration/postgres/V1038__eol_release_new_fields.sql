-- V1038: Add security support date, official source URL, and derived support phase to eol_release

ALTER TABLE eol_release
    ADD COLUMN IF NOT EXISTS security_support_date DATE,
    ADD COLUMN IF NOT EXISTS official_source_url   VARCHAR(500),
    ADD COLUMN IF NOT EXISTS support_phase         VARCHAR(30);
