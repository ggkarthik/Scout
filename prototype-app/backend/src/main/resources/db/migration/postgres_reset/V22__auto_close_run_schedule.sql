ALTER TABLE tenant_default.risk_policies
    ADD COLUMN IF NOT EXISTS auto_close_run_interval_days integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS auto_close_last_run_at timestamptz;
