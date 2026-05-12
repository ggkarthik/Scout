ALTER TABLE app_users
    ADD COLUMN IF NOT EXISTS password_setup_token_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS password_setup_token_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_app_users_password_setup_token_hash
    ON app_users (password_setup_token_hash);
