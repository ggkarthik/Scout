-- platform.tenant_entitlement_overrides is queried by TenantEntitlementService (loadTenantOverrides,
-- listOverrides, upsertOverride, deleteOverride, existingOverrideId) but was never created by a
-- migration, causing a BadSqlGrammarException (surfaced to callers as a generic 500) on any endpoint
-- that resolves tenant entitlements, e.g. POST /api/upgrade-recommendation.
CREATE TABLE IF NOT EXISTS platform.tenant_entitlement_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    entitlement_key varchar(128) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    reason varchar(500),
    expires_at timestamptz,
    created_by uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_tenant_entitlement_overrides_tenant_key UNIQUE (tenant_id, entitlement_key),
    CONSTRAINT fk_tenant_entitlement_overrides_tenant
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_entitlement_overrides_entitlement_key
        FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions (key)
);

CREATE INDEX IF NOT EXISTS idx_tenant_entitlement_overrides_tenant ON platform.tenant_entitlement_overrides (tenant_id);
