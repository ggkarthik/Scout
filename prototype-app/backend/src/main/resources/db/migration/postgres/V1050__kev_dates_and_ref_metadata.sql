-- Add CISA KEV date fields to vulnerabilities
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS kev_date_added    DATE,
    ADD COLUMN IF NOT EXISTS kev_due_date      DATE,
    ADD COLUMN IF NOT EXISTS kev_required_action VARCHAR(500);
