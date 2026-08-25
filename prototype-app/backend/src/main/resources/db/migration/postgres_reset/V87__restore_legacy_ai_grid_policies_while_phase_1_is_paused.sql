-- migration-guard: platform-only
-- V76 installed the Phase 1 catalog and retired the predecessor policies.  Phase 1 is
-- subsequently held at VALIDATED/PAUSED until its external certification gates pass.
-- Keep the previously released controls operating during that hold; a governed
-- migration can retire each predecessor only when its replacement is approved.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM platform.ai_grid_policy_versions
         WHERE release_family = 'AGCF_PHASE_1'
           AND lifecycle = 'PUBLISHED'
    ) THEN
        UPDATE platform.ai_grid_policy_versions
           SET lifecycle = 'PUBLISHED'
         WHERE policy_id NOT LIKE 'AGCF-%'
           AND lifecycle = 'RETIRED';

        UPDATE platform.ai_grid_policy_distribution
           SET available = default_selection <> 'DISABLED',
               rollout_stage = CASE
                   WHEN default_selection = 'DISABLED' THEN 'PAUSED'
                   ELSE 'GENERAL_AVAILABILITY'
               END,
               updated_by = 'ai-grid-phase-1-release-safety',
               updated_at = now()
         WHERE policy_id NOT LIKE 'AGCF-%'
           AND rollout_stage = 'RETIRED';
    END IF;
END $$;
