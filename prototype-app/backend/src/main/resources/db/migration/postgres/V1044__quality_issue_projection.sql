CREATE TABLE IF NOT EXISTS quality_issue_projection (
    id TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issue_key TEXT NOT NULL,
    domain TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    source_object_type TEXT NOT NULL,
    source_object_id TEXT,
    asset_id UUID,
    component_id UUID,
    software_identity_id UUID,
    vulnerability_id UUID,
    sync_run_id UUID,
    title TEXT NOT NULL,
    primary_label TEXT,
    secondary_label TEXT,
    asset_type TEXT,
    source_system TEXT,
    ecosystem TEXT,
    affects_active_findings BOOLEAN NOT NULL DEFAULT FALSE,
    affected_asset_count BIGINT NOT NULL DEFAULT 0,
    affected_component_count BIGINT NOT NULL DEFAULT 0,
    open_finding_count BIGINT NOT NULL DEFAULT 0,
    open_vulnerability_count BIGINT NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    drilldown_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    CONSTRAINT uk_quality_issue_projection_tenant_issue UNIQUE (tenant_id, issue_key)
);

CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_domain
    ON quality_issue_projection (tenant_id, domain, severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_filters
    ON quality_issue_projection (
        tenant_id,
        affects_active_findings,
        asset_type,
        source_system,
        ecosystem
    );

CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_refs
    ON quality_issue_projection (
        tenant_id,
        vulnerability_id,
        software_identity_id,
        component_id,
        asset_id
    );
