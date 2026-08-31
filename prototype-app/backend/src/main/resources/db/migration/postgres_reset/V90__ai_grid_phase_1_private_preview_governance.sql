-- migration-guard: platform-only
-- Private customer-validation governance is deliberately separate from the
-- seven-gate GA release board.  Policy rows remain unavailable until the
-- preview controls record an explicit, all-or-nothing admission decision.
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_preview_release (
    release_family varchar(64) PRIMARY KEY,
    manifest_digest varchar(64) NOT NULL,
    total_policies integer NOT NULL,
    state varchar(32) NOT NULL DEFAULT 'PAUSED',
    internal_tenant_id uuid,
    approved_cohort_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_approved_cohort_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    approved_by varchar(255),
    approved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (state IN ('PAUSED','READY','PROMOTED','INVALIDATED')),
    CHECK (jsonb_typeof(approved_cohort_json) = 'array'),
    CHECK (jsonb_typeof(last_approved_cohort_json) = 'array')
);

CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_preview_gate_evidence (
    gate_key varchar(64) PRIMARY KEY,
    status varchar(16) NOT NULL DEFAULT 'PENDING',
    evidence_ref varchar(1024),
    results_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    recorded_by varchar(255),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status IN ('PENDING','PASSED','FAILED')),
    CHECK (jsonb_typeof(results_json) = 'object')
);

INSERT INTO platform.ai_grid_phase_1_preview_release
    (release_family, manifest_digest, total_policies)
SELECT 'AGCF_PHASE_1',
       md5(string_agg(coalesce(package_digest, ''), ',' ORDER BY policy_id, version)),
       count(*)
  FROM platform.ai_grid_policy_versions
 WHERE release_family = 'AGCF_PHASE_1';

INSERT INTO platform.ai_grid_phase_1_preview_gate_evidence (gate_key)
VALUES
    ('CATALOG_BROWSER_E2E'),
    ('CERTIFICATION_246'),
    ('SECURITY_SMOKE'),
    ('PERFORMANCE_SMOKE'),
    ('ROLLBACK_SMOKE'),
    ('INTERNAL_CANARY')
ON CONFLICT (gate_key) DO NOTHING;

-- Any package-digest change invalidates a previous private-preview decision.
CREATE OR REPLACE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.release_family = 'AGCF_PHASE_1'
       AND NEW.release_family = 'AGCF_PHASE_1'
       AND coalesce(OLD.package_digest, '') <> coalesce(NEW.package_digest, '') THEN
        UPDATE platform.ai_grid_phase_1_preview_release
           SET state = 'INVALIDATED', approved_cohort_json = '[]'::jsonb,
               updated_at = now()
         WHERE release_family = 'AGCF_PHASE_1';
        UPDATE platform.ai_grid_policy_distribution
           SET available = false, rollout_stage = 'PAUSED',
               canary_tenant_ids_json = '[]'::jsonb, updated_at = now()
         WHERE policy_id = NEW.policy_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ai_grid_phase_1_preview_digest_change
    ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_phase_1_preview_digest_change
AFTER UPDATE OF package_digest ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change();
