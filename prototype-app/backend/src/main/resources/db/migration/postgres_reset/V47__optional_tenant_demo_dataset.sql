-- migration-guard: platform-only
ALTER TABLE platform.tenants
    ADD COLUMN IF NOT EXISTS demo_data_requested boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS demo_data_status varchar(32) NOT NULL DEFAULT 'NOT_REQUESTED',
    ADD COLUMN IF NOT EXISTS demo_data_version varchar(64),
    ADD COLUMN IF NOT EXISTS demo_data_seeded_at timestamptz,
    ADD COLUMN IF NOT EXISTS demo_data_error varchar(2000);

ALTER TABLE platform.tenants
    DROP CONSTRAINT IF EXISTS tenants_demo_data_status_check;

ALTER TABLE platform.tenants
    ADD CONSTRAINT tenants_demo_data_status_check
        CHECK (demo_data_status IN ('NOT_REQUESTED', 'REQUESTED', 'SEEDING', 'SEEDED', 'FAILED'));

CREATE INDEX IF NOT EXISTS idx_tenants_demo_data_work
    ON platform.tenants (demo_data_requested, demo_data_status, status)
    WHERE demo_data_requested = true;
