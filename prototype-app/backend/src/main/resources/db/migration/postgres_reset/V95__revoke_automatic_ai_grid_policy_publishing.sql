-- migration-guard: platform-only
-- V91 installed the reviewed package bytes but also promoted every package to
-- PUBLISHED and made it generally available.  Installation must not constitute
-- approval or tenant distribution: those actions remain explicit governance
-- operations.

UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED',
       approved_by = NULL,
       approved_at = NULL,
       published_at = NULL
 WHERE policy_id LIKE 'AGCF-%'
   AND package_source_ref LIKE 'policy-packages/agcf/%'
   AND lifecycle = 'PUBLISHED'
   AND approved_by = 'ai-grid-package-compiler';

UPDATE platform.ai_grid_policy_distribution
   SET available = false,
       rollout_stage = 'PAUSED',
       canary_tenant_ids_json = '[]'::jsonb,
       pinned_version = NULL,
       updated_by = 'ai-grid-shipping-correction',
       updated_at = now()
 WHERE policy_id LIKE 'AGCF-%'
   AND updated_by = 'ai-grid-package-compiler';
