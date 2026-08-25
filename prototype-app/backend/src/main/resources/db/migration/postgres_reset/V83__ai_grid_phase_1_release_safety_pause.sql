-- migration-guard: platform-only
-- Phase 1 catalog records are installed before external certification, but they must never be
-- tenant-visible or published until the governed release gate approves their package digest.
UPDATE platform.ai_grid_policy_distribution d
   SET available = false, rollout_stage = 'PAUSED', updated_by = 'ai-grid-phase-1-release-safety', updated_at = now()
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p
                WHERE p.policy_id = d.policy_id AND p.release_family = 'AGCF_PHASE_1')
   AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions decision
                    JOIN platform.ai_grid_policy_versions p ON p.policy_id = decision.policy_id
                        AND p.version = decision.policy_version
                   WHERE decision.policy_id = d.policy_id AND decision.decision = 'APPROVED'
                     AND p.release_family = 'AGCF_PHASE_1');

UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED', approved_by = null, approved_at = null, published_at = null
 WHERE release_family = 'AGCF_PHASE_1' AND lifecycle = 'PUBLISHED'
   AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions decision
                   WHERE decision.policy_id = ai_grid_policy_versions.policy_id
                     AND decision.policy_version = ai_grid_policy_versions.version
                     AND decision.decision = 'APPROVED');
