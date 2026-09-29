-- migration-guard: tenant-only
--
-- Daily admission budget for AI-BOM projection (Milestone 2 part 4.5). Deliberately not
-- ai_grid_facts' sibling ai_grid_budget_admissions: that table is keyed by a connector run_id
-- and tracks cadence rules for recurring scheduled scans, neither of which apply to a job
-- triggered by a document upload. A different provider label alone would not isolate this
-- budget from that one, so this gets its own small counter instead.

CREATE TABLE ${tenantSchema}.ai_bom_projection_admissions (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    admission_date date NOT NULL,
    admitted_count integer NOT NULL DEFAULT 0,
    throttled_count integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, admission_date),
    CONSTRAINT ai_bom_projection_admissions_admitted_count_check CHECK (admitted_count >= 0),
    CONSTRAINT ai_bom_projection_admissions_throttled_count_check CHECK (throttled_count >= 0)
);

ALTER TABLE ${tenantSchema}.ai_bom_projection_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_projection_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_projection_admissions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
