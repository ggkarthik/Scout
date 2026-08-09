-- migration-guard: platform-only
-- Canonical platform release and distribution state.  It is intentionally
-- independent of tenant selection and policy lifecycle.
CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_distribution (
    policy_id varchar(128) PRIMARY KEY,
    available boolean NOT NULL DEFAULT true,
    default_selection varchar(32) NOT NULL DEFAULT 'ENABLED',
    rollout_stage varchar(32) NOT NULL DEFAULT 'GENERAL_AVAILABILITY',
    canary_tenant_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    pinned_version varchar(32),
    updated_by varchar(255) NOT NULL DEFAULT 'ai-grid-bootstrap',
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (default_selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    CHECK (rollout_stage IN ('GENERAL_AVAILABILITY','CANARY','PAUSED','RETIRED'))
);

ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS package_digest varchar(64),
    ADD COLUMN IF NOT EXISTS package_source_ref varchar(1024),
    ADD COLUMN IF NOT EXISTS authored_by varchar(255),
    ADD COLUMN IF NOT EXISTS release_notes text,
    ADD COLUMN IF NOT EXISTS replaces_policy_id varchar(128),
    ADD COLUMN IF NOT EXISTS replaces_version varchar(32);

UPDATE platform.ai_grid_policy_versions
   SET authored_by = coalesce(authored_by, approved_by, 'ai-grid-bootstrap')
 WHERE authored_by IS NULL;

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id, available, default_selection, rollout_stage, updated_by)
SELECT DISTINCT ON (policy_id)
       policy_id, true, default_selection, 'GENERAL_AVAILABILITY', 'ai-grid-catalog-migration'
  FROM platform.ai_grid_policy_versions
 WHERE lifecycle = 'PUBLISHED'
 ORDER BY policy_id, published_at DESC NULLS LAST, version DESC
ON CONFLICT (policy_id) DO NOTHING;

-- Keep the legacy distribution populated during the staged migration.  The
-- governed catalog is authoritative for new reads and evaluations.
INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled, updated_by)
SELECT policy_id, available, default_selection IN ('REQUIRED','ENABLED'), 'ai-grid-catalog-migration'
  FROM platform.ai_grid_policy_distribution
ON CONFLICT (policy_id) DO NOTHING;
