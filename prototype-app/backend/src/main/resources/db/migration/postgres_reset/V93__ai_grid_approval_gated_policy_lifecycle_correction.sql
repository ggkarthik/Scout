-- migration-guard: platform-only
-- Forward-only correction for approval-gated AI Grid policy lifecycle.

ALTER TABLE platform.ai_grid_policy_release_decisions
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_by varchar(255),
    ADD COLUMN IF NOT EXISTS revocation_reason text;
ALTER TABLE platform.ai_grid_policy_release_decisions
    DROP CONSTRAINT IF EXISTS ai_grid_release_decision_digest_check;
ALTER TABLE platform.ai_grid_policy_release_decisions
    ADD CONSTRAINT ai_grid_release_decision_digest_check
    CHECK (decision <> 'APPROVED' OR (package_digest IS NOT NULL AND btrim(package_digest) <> ''));

ALTER TABLE platform.ai_grid_policy_rollouts
    ADD COLUMN IF NOT EXISTS approved_package_digest varchar(64),
    ADD COLUMN IF NOT EXISTS release_decision_id uuid;
ALTER TABLE platform.ai_grid_policy_rollout_tasks
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollout_tasks_status_check;
ALTER TABLE platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_status_check
    CHECK (status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','COMPLETED','FAILED','CANCELED'));
ALTER TABLE platform.ai_grid_policy_rollouts
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollouts_status_check;
ALTER TABLE platform.ai_grid_policy_rollouts
    ADD CONSTRAINT ai_grid_policy_rollouts_status_check
    CHECK (status IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELED'));

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT IF EXISTS ai_grid_policy_active_digest_check;
UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED', published_at = NULL
 WHERE lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
   AND (package_digest IS NULL OR btrim(package_digest) = '');
ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_active_digest_check
    CHECK (lifecycle NOT IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
           OR (package_digest IS NOT NULL AND btrim(package_digest) <> '')
           OR (coalesce(release_family, '') <> 'AGCF_PHASE_1' AND package_source_ref IS NULL));

-- V91 compiler decisions are historical audit rows, never authorization.
UPDATE platform.ai_grid_policy_release_decisions
   SET revoked_at = coalesce(revoked_at, now()),
       revoked_by = coalesce(revoked_by, 'ai-grid-v93-migration'),
       revocation_reason = coalesce(revocation_reason, 'V91 compiler approval revoked; fresh human approval required')
 WHERE decided_by = 'ai-grid-package-compiler' AND revoked_at IS NULL;
UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED', published_at = NULL
 WHERE policy_id LIKE 'AGCF-%' AND package_source_ref LIKE 'policy-packages/agcf/%';
UPDATE platform.ai_grid_policy_distribution
   SET available = false, rollout_stage = 'PAUSED', default_selection = 'DISABLED',
       canary_tenant_ids_json = '[]'::jsonb, pinned_version = NULL,
       approved_package_digest = NULL, release_decision_id = NULL,
       updated_by = 'ai-grid-v93-migration', updated_at = now()
 WHERE policy_id LIKE 'AGCF-%';

-- Keep the pre-Phase-1 compatibility catalog operating while the Phase-1 packages
-- are reset for fresh human approval.
UPDATE platform.ai_grid_policy_versions
   SET package_digest = coalesce(package_digest, md5('AI_GRID_LEGACY_COMPAT:' || policy_id || ':' || version))
 WHERE policy_id NOT LIKE 'AGCF-%'
   AND coalesce(release_family, '') <> 'AGCF_PHASE_1'
   AND lifecycle IN ('RETIRED','VALIDATED');
INSERT INTO platform.ai_grid_policy_release_decisions
    (id, policy_id, policy_version, package_digest, decision, reason, decided_by)
SELECT md5('AI_GRID_LEGACY_COMPAT_APPROVAL:' || p.policy_id || ':' || p.version)::uuid,
       p.policy_id, p.version, p.package_digest, 'APPROVED',
       'Pre-Phase-1 legacy compatibility approval; not a Phase-1 package shipment',
       'ai-grid-legacy-compatibility'
  FROM platform.ai_grid_policy_versions p
 WHERE p.policy_id NOT LIKE 'AGCF-%'
   AND coalesce(p.release_family, '') <> 'AGCF_PHASE_1'
   AND p.lifecycle IN ('RETIRED','VALIDATED')
   AND p.package_digest IS NOT NULL
ON CONFLICT (id) DO NOTHING;
UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'PUBLISHED'
 WHERE policy_id NOT LIKE 'AGCF-%'
   AND coalesce(release_family, '') <> 'AGCF_PHASE_1'
   AND lifecycle IN ('RETIRED','VALIDATED');
UPDATE platform.ai_grid_policy_distribution d
   SET available = d.default_selection <> 'DISABLED',
       rollout_stage = CASE WHEN d.default_selection = 'DISABLED' THEN 'PAUSED' ELSE 'GENERAL_AVAILABILITY' END,
       pinned_version = p.version, approved_package_digest = p.package_digest,
       release_decision_id = r.id,
       updated_by = 'ai-grid-v93-legacy-compatibility', updated_at = now()
  FROM platform.ai_grid_policy_versions p
  JOIN platform.ai_grid_policy_release_decisions r
    ON r.policy_id = p.policy_id AND r.policy_version = p.version
   AND r.package_digest = p.package_digest AND r.decision = 'APPROVED'
 WHERE d.policy_id = p.policy_id
   AND p.policy_id NOT LIKE 'AGCF-%'
   AND coalesce(p.release_family, '') <> 'AGCF_PHASE_1'
   AND p.lifecycle = 'PUBLISHED';

UPDATE platform.ai_grid_policy_rollout_tasks
   SET status = 'CANCELED', failure_detail = 'Canceled by V93 approval-gated lifecycle migration', updated_at = now()
 WHERE status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','FAILED');
UPDATE platform.ai_grid_policy_rollouts
   SET status = 'CANCELED', completed_at = coalesce(completed_at, now())
 WHERE status IN ('PENDING','PROCESSING','FAILED');

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_inactivation_tasks (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    reason varchar(64) NOT NULL DEFAULT 'PLATFORM_DEPRECATED',
    status varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz,
    failure_detail text,
    queued_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_id, tenant_id),
    CHECK (reason IN ('PLATFORM_DEPRECATED')),
    CHECK (status IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELED'))
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_inactivation_claim
    ON platform.ai_grid_policy_inactivation_tasks (status, next_retry_at, queued_at);

CREATE OR REPLACE FUNCTION platform.ai_grid_approved_decision_matches(
    candidate_policy_id varchar, candidate_version varchar, candidate_digest varchar, candidate_decision uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT candidate_digest IS NOT NULL AND btrim(candidate_digest) <> ''
       AND candidate_decision IS NOT NULL
       AND EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions d
                    WHERE d.id = candidate_decision AND d.policy_id = candidate_policy_id
                      AND d.policy_version = candidate_version AND d.package_digest = candidate_digest
                      AND d.decision = 'APPROVED' AND d.revoked_at IS NULL)
$$;

CREATE OR REPLACE FUNCTION platform.require_ai_grid_approved_package()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
       AND NEW.package_digest IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions d
                       WHERE d.policy_id = NEW.policy_id AND d.policy_version = NEW.version
                         AND d.package_digest = NEW.package_digest AND d.decision = 'APPROVED'
                         AND d.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Active policy lifecycle requires an exact unrevoked approval and digest';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_grid_approved_package_publication ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_approved_package_publication
BEFORE INSERT OR UPDATE OF lifecycle, package_digest ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_approved_package();

CREATE OR REPLACE FUNCTION platform.prevent_ai_grid_approved_package_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
       AND OLD.package_digest IS NOT NULL
       AND OLD.package_source_ref LIKE 'policy-packages/agcf/%' AND (
       OLD.name IS DISTINCT FROM NEW.name OR OLD.description IS DISTINCT FROM NEW.description OR
       OLD.severity IS DISTINCT FROM NEW.severity OR OLD.workflow_class IS DISTINCT FROM NEW.workflow_class OR
       OLD.default_selection IS DISTINCT FROM NEW.default_selection OR OLD.artifact_types_json IS DISTINCT FROM NEW.artifact_types_json OR
       OLD.native_kinds_json IS DISTINCT FROM NEW.native_kinds_json OR OLD.required_capabilities_json IS DISTINCT FROM NEW.required_capabilities_json OR
       OLD.required_relationships_json IS DISTINCT FROM NEW.required_relationships_json OR OLD.required_resource_families_json IS DISTINCT FROM NEW.required_resource_families_json OR
       OLD.required_facts_json IS DISTINCT FROM NEW.required_facts_json OR OLD.predicate_json IS DISTINCT FROM NEW.predicate_json OR
       OLD.reason_code IS DISTINCT FROM NEW.reason_code OR OLD.remediation IS DISTINCT FROM NEW.remediation OR
       OLD.framework_mappings_json IS DISTINCT FROM NEW.framework_mappings_json OR OLD.scope_resolution IS DISTINCT FROM NEW.scope_resolution OR
       OLD.parameter_definitions_json IS DISTINCT FROM NEW.parameter_definitions_json OR OLD.package_digest IS DISTINCT FROM NEW.package_digest OR
       OLD.package_source_ref IS DISTINCT FROM NEW.package_source_ref OR OLD.release_notes IS DISTINCT FROM NEW.release_notes OR
       OLD.release_family IS DISTINCT FROM NEW.release_family OR OLD.release_wave IS DISTINCT FROM NEW.release_wave) THEN
        RAISE EXCEPTION 'Approved, canary, published, or deprecated policy packages are immutable';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_grid_approved_package_immutable ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_approved_package_immutable
BEFORE UPDATE ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.prevent_ai_grid_approved_package_mutation();

CREATE OR REPLACE FUNCTION platform.require_ai_grid_distribution_approval()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pinned platform.ai_grid_policy_versions%ROWTYPE;
BEGIN
    IF NEW.available OR NEW.rollout_stage IN ('GENERAL_AVAILABILITY','CANARY') OR NEW.pinned_version IS NOT NULL THEN
        IF NEW.pinned_version IS NULL THEN RAISE EXCEPTION 'Active distribution requires a pinned version'; END IF;
        SELECT * INTO pinned FROM platform.ai_grid_policy_versions
         WHERE policy_id = NEW.policy_id AND version = NEW.pinned_version;
        IF FOUND AND pinned.package_digest IS NULL THEN RETURN NEW; END IF;
        IF NOT FOUND OR pinned.lifecycle NOT IN ('PUBLISHED','CANARY','DEPRECATED')
           OR NOT platform.ai_grid_approved_decision_matches(NEW.policy_id, NEW.pinned_version,
                                                              NEW.approved_package_digest, NEW.release_decision_id)
           OR pinned.package_digest <> NEW.approved_package_digest THEN
            RAISE EXCEPTION 'Distribution requires an exact unrevoked approval binding';
        END IF;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_grid_distribution_approval ON platform.ai_grid_policy_distribution;
CREATE TRIGGER trg_ai_grid_distribution_approval
BEFORE INSERT OR UPDATE ON platform.ai_grid_policy_distribution
FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_distribution_approval();

CREATE OR REPLACE FUNCTION platform.require_ai_grid_rollout_approval()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT platform.ai_grid_approved_decision_matches(NEW.policy_id, NEW.new_version,
                                                       NEW.approved_package_digest, NEW.release_decision_id)
       OR NEW.package_digest <> NEW.approved_package_digest THEN
        RAISE EXCEPTION 'Rollout requires an exact unrevoked approval binding';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_grid_rollout_approval ON platform.ai_grid_policy_rollouts;
CREATE TRIGGER trg_ai_grid_rollout_approval
BEFORE INSERT OR UPDATE OF policy_id, new_version, package_digest, approved_package_digest, release_decision_id
ON platform.ai_grid_policy_rollouts FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_rollout_approval();

CREATE OR REPLACE FUNCTION platform.pause_ai_grid_revoked_distribution()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
        UPDATE platform.ai_grid_policy_distribution
           SET available=false, rollout_stage='PAUSED', default_selection='DISABLED',
               canary_tenant_ids_json='[]'::jsonb, updated_by=coalesce(NEW.revoked_by, 'ai-grid-revocation'), updated_at=now()
         WHERE policy_id=NEW.policy_id AND release_decision_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_grid_pause_revoked_distribution ON platform.ai_grid_policy_release_decisions;
CREATE TRIGGER trg_ai_grid_pause_revoked_distribution
AFTER UPDATE OF revoked_at ON platform.ai_grid_policy_release_decisions
FOR EACH ROW EXECUTE FUNCTION platform.pause_ai_grid_revoked_distribution();
