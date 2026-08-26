CREATE TABLE IF NOT EXISTS ai_grid_capability_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    capability_id varchar(128) NOT NULL,
    connector varchar(128) NOT NULL,
    account_id varchar(255) NOT NULL,
    region varchar(128) NOT NULL,
    resource_family varchar(128) NOT NULL,
    connector_version varchar(64),
    observed_at timestamptz NOT NULL,
    expires_at timestamptz,
    status varchar(32) NOT NULL CHECK (status IN ('COMPLETE','DISABLED','UNAUTHORIZED','UNSUPPORTED_API','PARTIAL','ERROR','STALE')),
    detail text,
    UNIQUE (tenant_id, run_id, provider, capability_id, account_id, region)
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_capability_observations_run ON ai_grid_capability_observations (run_id, provider, capability_id);
ALTER TABLE ai_grid_capability_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_capability_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_capability_observations;
CREATE POLICY tenant_isolation ON ai_grid_capability_observations
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
