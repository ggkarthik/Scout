ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS max_daily_exposure_refreshes integer NOT NULL DEFAULT 25;

ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_max_daily_exposure_refreshes_nonnegative
        CHECK (max_daily_exposure_refreshes >= 0) NOT VALID;
