-- Durable audit survives deletion of an unreferenced snapshot body.
CREATE TABLE IF NOT EXISTS ai_grid_retention_purge_audit (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL,
    content_hash varchar(64) NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    reason_code varchar(64) NOT NULL,
    purged_by varchar(255) NOT NULL,
    purged_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_retention_purge_audit_time
    ON ai_grid_retention_purge_audit (purged_at DESC);

ALTER TABLE ai_grid_retention_purge_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_retention_purge_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_retention_purge_audit;
CREATE POLICY tenant_isolation ON ai_grid_retention_purge_audit
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
