-- Tenant-side policy state records the platform baseline separately from tenant overrides.
ALTER TABLE ${tenantSchema}.ai_grid_policy_selections
    ADD COLUMN IF NOT EXISTS platform_policy_version varchar(32),
    ADD COLUMN IF NOT EXISTS platform_default_selection varchar(32),
    ADD COLUMN IF NOT EXISTS configuration_source varchar(32) NOT NULL DEFAULT 'PLATFORM_DEFAULT',
    ADD COLUMN IF NOT EXISTS tenant_configured_at timestamp with time zone;

ALTER TABLE ${tenantSchema}.ai_grid_policy_selections
    ADD CONSTRAINT ai_grid_policy_selection_source_check
    CHECK (configuration_source IN ('PLATFORM_DEFAULT', 'TENANT_OVERRIDE'));

COMMENT ON COLUMN ${tenantSchema}.ai_grid_policy_selections.configuration_source IS 'Platform default or an explicit tenant override; platform policy metadata remains read-only here.';

