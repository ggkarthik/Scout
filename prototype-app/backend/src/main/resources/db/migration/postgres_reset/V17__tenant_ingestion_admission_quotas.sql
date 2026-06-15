ALTER TABLE platform.tenants
    ADD COLUMN IF NOT EXISTS sbom_rate_limit_window_seconds INTEGER,
    ADD COLUMN IF NOT EXISTS max_sbom_jobs_per_rate_limit_window INTEGER,
    ADD COLUMN IF NOT EXISTS max_active_sbom_jobs INTEGER;
