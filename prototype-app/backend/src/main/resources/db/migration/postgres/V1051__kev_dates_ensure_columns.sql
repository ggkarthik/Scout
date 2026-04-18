-- Ensure CISA KEV date columns exist (idempotent guard for V1050 partial-apply)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='vulnerabilities' AND column_name='kev_date_added') THEN
        ALTER TABLE vulnerabilities ADD COLUMN kev_date_added DATE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='vulnerabilities' AND column_name='kev_due_date') THEN
        ALTER TABLE vulnerabilities ADD COLUMN kev_due_date DATE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='vulnerabilities' AND column_name='kev_required_action') THEN
        ALTER TABLE vulnerabilities ADD COLUMN kev_required_action VARCHAR(500);
    END IF;
END $$;
