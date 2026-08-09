-- migration-guard: platform-only
-- Records the deliberately irreversible, one-time clean-slate operation.
CREATE TABLE IF NOT EXISTS platform.ai_grid_test_data_reset_log (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    reset_by varchar(255) NOT NULL,
    reset_at timestamptz NOT NULL DEFAULT now(),
    tenant_count integer NOT NULL,
    confirmation_digest varchar(64) NOT NULL
);
