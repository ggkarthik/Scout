-- migration-guard: platform-only
-- Independent policy lifecycle and digest-bound release governance.

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT IF EXISTS ai_grid_policy_versions_lifecycle_check;
ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_versions_lifecycle_check
    CHECK (lifecycle IN ('DRAFT','VALIDATED','APPROVED','CANARY','PUBLISHED','DEPRECATED','RETIRED'));

ALTER TABLE platform.ai_grid_policy_release_decisions
    ADD COLUMN IF NOT EXISTS package_digest varchar(64);

ALTER TABLE platform.ai_grid_policy_distribution
    ADD COLUMN IF NOT EXISTS approved_package_digest varchar(64),
    ADD COLUMN IF NOT EXISTS release_decision_id uuid;

CREATE INDEX IF NOT EXISTS idx_ai_grid_release_decisions_digest
    ON platform.ai_grid_policy_release_decisions (policy_id, policy_version, package_digest, decision, decided_at DESC);

-- V91 is the source-controlled initial package shipment. Preserve that reviewed
-- shipment by materializing its digest-bound approval in the policy ledger before
-- applying the trust reset below. Future publications must use the normal
-- independent approval workflow.
INSERT INTO platform.ai_grid_policy_release_decisions
    (id, policy_id, policy_version, package_digest, decision, reason, decided_by)
SELECT md5('AI_GRID_V91_SHIPMENT:' || p.policy_id || ':' || p.version || ':' || p.package_digest)::uuid,
       p.policy_id, p.version, p.package_digest, 'APPROVED',
       'Source-controlled V91 initial package shipment', 'ai-grid-package-compiler'
  FROM platform.ai_grid_policy_versions p
 WHERE p.policy_id LIKE 'AGCF-%'
   AND p.package_source_ref LIKE 'policy-packages/agcf/%'
   AND p.lifecycle = 'PUBLISHED'
   AND p.package_digest IS NOT NULL
   AND NOT EXISTS (
       SELECT 1
         FROM platform.ai_grid_policy_release_decisions d
        WHERE d.policy_id = p.policy_id
          AND d.policy_version = p.version
          AND d.decision = 'APPROVED'
          AND d.package_digest = p.package_digest
   );

-- Existing bundled publications without a digest-bound approval are not trusted.
-- Their history remains in the release-decision ledger, but they must be manually
-- approved again before distribution.
UPDATE platform.ai_grid_policy_versions p
   SET lifecycle = 'VALIDATED', published_at = NULL
 WHERE p.lifecycle = 'PUBLISHED'
   AND NOT EXISTS (
       SELECT 1
         FROM platform.ai_grid_policy_release_decisions d
        WHERE d.policy_id = p.policy_id
          AND d.policy_version = p.version
          AND d.decision = 'APPROVED'
          AND d.package_digest IS NOT NULL
          AND d.package_digest = p.package_digest
   );

UPDATE platform.ai_grid_policy_distribution d
   SET available = false, rollout_stage = 'PAUSED',
       canary_tenant_ids_json = '[]'::jsonb,
       approved_package_digest = NULL, release_decision_id = NULL,
       updated_at = now()
 WHERE NOT EXISTS (
       SELECT 1
         FROM platform.ai_grid_policy_versions p
         JOIN platform.ai_grid_policy_release_decisions r
           ON r.policy_id = p.policy_id AND r.policy_version = p.version
          AND r.decision = 'APPROVED'
          AND r.package_digest IS NOT NULL
          AND r.package_digest = p.package_digest
        WHERE p.policy_id = d.policy_id AND p.lifecycle IN ('PUBLISHED','DEPRECATED')
   );

UPDATE platform.ai_grid_policy_distribution d
   SET approved_package_digest = p.package_digest,
       release_decision_id = r.id,
       updated_at = now()
  FROM platform.ai_grid_policy_versions p
  JOIN LATERAL (
      SELECT id
        FROM platform.ai_grid_policy_release_decisions
       WHERE policy_id = p.policy_id
         AND policy_version = p.version
         AND decision = 'APPROVED'
         AND package_digest = p.package_digest
       ORDER BY decided_at DESC
       LIMIT 1
  ) r ON true
 WHERE d.policy_id = p.policy_id
   AND p.lifecycle IN ('PUBLISHED','DEPRECATED');

CREATE OR REPLACE FUNCTION platform.require_ai_grid_approved_package()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.lifecycle = 'PUBLISHED' AND NOT EXISTS (
        SELECT 1
          FROM platform.ai_grid_policy_release_decisions d
         WHERE d.policy_id = NEW.policy_id
           AND d.policy_version = NEW.version
           AND d.decision = 'APPROVED'
           AND d.package_digest IS NOT NULL
           AND d.package_digest = NEW.package_digest
    ) THEN
        RAISE EXCEPTION 'Policy publication requires an APPROVED decision for the exact package digest';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ai_grid_approved_package_publication
    ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_approved_package_publication
BEFORE INSERT OR UPDATE OF lifecycle ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_approved_package();

CREATE OR REPLACE FUNCTION platform.prevent_ai_grid_approved_package_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED') AND (
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
        OLD.control_objective_id IS DISTINCT FROM NEW.control_objective_id OR OLD.provider IS DISTINCT FROM NEW.provider OR
        OLD.evaluation_mode IS DISTINCT FROM NEW.evaluation_mode OR OLD.evaluation_definition_json IS DISTINCT FROM NEW.evaluation_definition_json OR
        OLD.base_evidence_tiers_json IS DISTINCT FROM NEW.base_evidence_tiers_json OR OLD.conditional_capabilities_json IS DISTINCT FROM NEW.conditional_capabilities_json OR
        OLD.certification_parameter_profile_json IS DISTINCT FROM NEW.certification_parameter_profile_json OR OLD.release_family IS DISTINCT FROM NEW.release_family OR
        OLD.release_wave IS DISTINCT FROM NEW.release_wave
    ) THEN
        RAISE EXCEPTION 'Approved or published policy packages are immutable; create a new policy version';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ai_grid_approved_package_immutable
    ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_approved_package_immutable
BEFORE UPDATE ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.prevent_ai_grid_approved_package_mutation();

CREATE OR REPLACE FUNCTION platform.require_ai_grid_distribution_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    approved boolean;
BEGIN
    IF NEW.available OR NEW.rollout_stage IN ('GENERAL_AVAILABILITY','CANARY') OR NEW.pinned_version IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1
              FROM platform.ai_grid_policy_versions p
              JOIN platform.ai_grid_policy_release_decisions r
                ON r.policy_id = p.policy_id AND r.policy_version = p.version
               AND r.decision = 'APPROVED'
               AND r.package_digest IS NOT NULL
               AND r.package_digest = p.package_digest
             WHERE p.policy_id = NEW.policy_id
               AND p.lifecycle IN ('PUBLISHED','DEPRECATED')
               AND (NEW.pinned_version IS NULL OR p.version = NEW.pinned_version)
               AND NEW.approved_package_digest = r.package_digest
               AND NEW.release_decision_id = r.id
        ) INTO approved;
        IF NOT approved THEN
            RAISE EXCEPTION 'Distribution requires an exact approved package digest and release decision';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ai_grid_distribution_approval
    ON platform.ai_grid_policy_distribution;
CREATE TRIGGER trg_ai_grid_distribution_approval
BEFORE INSERT OR UPDATE ON platform.ai_grid_policy_distribution
FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_distribution_approval();
