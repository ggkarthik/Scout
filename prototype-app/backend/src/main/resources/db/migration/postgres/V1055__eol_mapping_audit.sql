-- Add audit columns to software_eol_mapping for compliance tracking of manual confirmations.
ALTER TABLE software_eol_mapping
    ADD COLUMN IF NOT EXISTS confirmed_by   VARCHAR(200),
    ADD COLUMN IF NOT EXISTS confirmed_at   TIMESTAMP,
    ADD COLUMN IF NOT EXISTS previous_slug  VARCHAR(200);
