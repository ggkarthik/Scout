-- migration-guard: tenant-only
-- Generated from the clean platform V1 migration ledger.  Keep this CTE's values
-- in exact-set parity with postgres_reset/V2__remove_legacy_ai_grid_migration.sql.
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL')),
legacy_findings(id) AS (
    SELECT f.id FROM findings f
     WHERE f.finding_kind = 'AI_POSTURE' AND f.policy_id IN (SELECT policy_id FROM legacy_ids)
)
DELETE FROM finding_comments WHERE finding_id IN (SELECT id FROM legacy_findings);

WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL')),
legacy_findings(id) AS (
    SELECT f.id FROM findings f
     WHERE f.finding_kind = 'AI_POSTURE' AND f.policy_id IN (SELECT policy_id FROM legacy_ids)
)
DELETE FROM finding_events WHERE finding_id IN (SELECT id FROM legacy_findings);

WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL')),
legacy_findings(id) AS (
    SELECT f.id FROM findings f
     WHERE f.finding_kind = 'AI_POSTURE' AND f.policy_id IN (SELECT policy_id FROM legacy_ids)
)
DELETE FROM findings WHERE id IN (SELECT id FROM legacy_findings);

WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_artifact_overrides WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_parameters WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_readiness WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_scopes WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_selection_history WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_policy_selections WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_current_expected_candidates WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_coverage_gaps WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_setup_actions WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
WITH legacy_ids(policy_id) AS (VALUES ('AWS_BEDROCK_WEAK_GUARDRAIL'))
DELETE FROM ai_grid_assessments WHERE policy_id IN (SELECT policy_id FROM legacy_ids);
