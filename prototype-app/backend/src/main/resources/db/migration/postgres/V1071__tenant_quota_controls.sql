ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS max_connector_count integer NOT NULL DEFAULT 10,
    ADD COLUMN IF NOT EXISTS max_service_account_count integer NOT NULL DEFAULT 25,
    ADD COLUMN IF NOT EXISTS max_daily_sbom_uploads integer NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS max_export_rows integer NOT NULL DEFAULT 50000;

ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_max_connector_count_nonnegative
        CHECK (max_connector_count >= 0) NOT VALID,
    ADD CONSTRAINT chk_tenants_max_service_account_count_nonnegative
        CHECK (max_service_account_count >= 0) NOT VALID,
    ADD CONSTRAINT chk_tenants_max_daily_sbom_uploads_nonnegative
        CHECK (max_daily_sbom_uploads >= 0) NOT VALID,
    ADD CONSTRAINT chk_tenants_max_export_rows_nonnegative
        CHECK (max_export_rows >= 0) NOT VALID;
