-- migration-guard: tenant-only
ALTER TABLE ${tenantSchema}.ai_grid_capability_observations
    ADD COLUMN IF NOT EXISTS reason_code character varying(64),
    ADD COLUMN IF NOT EXISTS evidence_scopes_json jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN ${tenantSchema}.ai_grid_capability_observations.reason_code IS
    'Stable connector outcome reason; not an inferred provider capability.';
COMMENT ON COLUMN ${tenantSchema}.ai_grid_capability_observations.evidence_scopes_json IS
    'Scope keys that directly produced this capability observation.';
