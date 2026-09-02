-- migration-guard: platform-only
-- Phase 2 policy identity is replacement-based: a deprecated policy keeps its
-- audit history but can never be selected or evaluated again.

-- Some pre-V76 installations already contained the Phase 1 policy IDs.  The
-- original seed correctly avoided replacing them, but left their release
-- metadata/distribution rows absent.  Normalize that historical path without
-- publishing anything: package installation remains VALIDATED and PAUSED.
UPDATE platform.ai_grid_policy_versions
   SET release_family = coalesce(release_family, 'AGCF_PHASE_1'),
       release_wave = coalesce(release_wave, 'PHASE_1')
 WHERE policy_id LIKE 'AGCF-%';

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id, available, default_selection, rollout_stage, canary_tenant_ids_json, pinned_version, updated_by)
SELECT p.policy_id, false, p.default_selection, 'PAUSED', '[]'::jsonb, null,
       'ai-grid-lifecycle-normalization'
  FROM platform.ai_grid_policy_versions p
 WHERE p.policy_id LIKE 'AGCF-%'
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT IF EXISTS ai_grid_policy_versions_lifecycle_check;
ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_versions_lifecycle_check
    CHECK (lifecycle IN ('DRAFT','VALIDATED','APPROVED','CANARY','PUBLISHED','RETIRED','DEPRECATED'));

ALTER TABLE platform.ai_grid_policy_release_decisions
    ADD COLUMN IF NOT EXISTS approved_package_digest varchar(128);

CREATE OR REPLACE FUNCTION platform.ai_grid_policy_release_decisions_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'AI Grid policy release decisions are immutable';
END;
$$;

DROP TRIGGER IF EXISTS ai_grid_policy_release_decisions_immutable
    ON platform.ai_grid_policy_release_decisions;
CREATE TRIGGER ai_grid_policy_release_decisions_immutable
    BEFORE UPDATE OR DELETE ON platform.ai_grid_policy_release_decisions
    FOR EACH ROW EXECUTE FUNCTION platform.ai_grid_policy_release_decisions_immutable();

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_release_bindings (
    id uuid PRIMARY KEY,
    approval_decision_id uuid NOT NULL UNIQUE REFERENCES platform.ai_grid_policy_release_decisions(id),
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    approved_package_digest varchar(128) NOT NULL,
    distribution_snapshot_json jsonb NOT NULL,
    target_tenant_ids_json jsonb NOT NULL,
    bound_by varchar(255) NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT now(),
    state varchar(32) NOT NULL DEFAULT 'ACTIVE',
    revoked_at timestamptz,
    revoked_by varchar(255),
    revocation_reason text,
    CHECK (state IN ('ACTIVE','REVOKED','CANCELLED')),
    CHECK ((state = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL)
        OR (state <> 'ACTIVE' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
    UNIQUE (policy_id, policy_version, approved_package_digest)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_release_bindings_active
    ON platform.ai_grid_policy_release_bindings (policy_id, policy_version)
    WHERE state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_deprecations (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    reason text NOT NULL,
    successor_policy_id varchar(128),
    deprecated_by varchar(255) NOT NULL,
    deprecated_at timestamptz NOT NULL DEFAULT now(),
    idempotency_key varchar(128) NOT NULL,
    UNIQUE (policy_id, policy_version),
    UNIQUE (idempotency_key)
);

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_deprecation_tasks (
    id uuid PRIMARY KEY,
    deprecation_id uuid NOT NULL REFERENCES platform.ai_grid_policy_deprecations(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    state varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz,
    failure_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (deprecation_id, tenant_id),
    CHECK (state IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELLED'))
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_deprecation_tasks_claim
    ON platform.ai_grid_policy_deprecation_tasks (state, next_retry_at, created_at);
