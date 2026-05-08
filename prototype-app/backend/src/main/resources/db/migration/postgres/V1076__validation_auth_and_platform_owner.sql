ALTER TABLE app_users
    ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255),
    ADD COLUMN IF NOT EXISTS password_set_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS platform_owner BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_app_users_lower_email
    ON app_users (lower(email));
