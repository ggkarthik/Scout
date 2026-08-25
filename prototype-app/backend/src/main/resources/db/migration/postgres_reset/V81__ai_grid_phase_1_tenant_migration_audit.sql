-- migration-guard: platform-only
-- Immutable operator record for a tenant-scoped application of the approved Phase 1 ledger.
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_tenant_migration_audit (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    ledger_version varchar(64) NOT NULL,
    applied_by varchar(255) NOT NULL,
    legacy_selection_count integer NOT NULL,
    selection_copy_count integer NOT NULL,
    retirement_count integer NOT NULL,
    open_findings_closed integer NOT NULL,
    manual_configuration_review_count integer NOT NULL,
    actions_json jsonb NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_phase_1_migration_audit_tenant
    ON platform.ai_grid_phase_1_tenant_migration_audit (tenant_id, applied_at DESC);
