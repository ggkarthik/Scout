ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purge_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purge_status VARCHAR(32),
    ADD COLUMN IF NOT EXISTS purge_error VARCHAR(2000);

CREATE INDEX IF NOT EXISTS idx_tenants_demo_expiry_purge
    ON tenants (plan_code, demo_expires_at, purged_at);
