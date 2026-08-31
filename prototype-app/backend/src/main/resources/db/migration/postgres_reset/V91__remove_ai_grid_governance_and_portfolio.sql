-- migration-guard: platform-only
-- Cleanup stage after V90 stopped all governance, portfolio, and manual
-- migration traffic. Runtime provenance, digests, lifecycle, distribution,
-- framework mappings, and automatic rollout tables remain intact.

DROP TABLE IF EXISTS platform.ai_grid_phase_1_release_gate_evidence CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_policy_release_decisions CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_precision_adjudications CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_precision_labels CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_precision_samples CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_precision_reviews CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_answer_key_results CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_answer_key_runs CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_answer_key_cases CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_answer_key_environments CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_policy_candidates CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_policy_migration_ledger CASCADE;
DROP TABLE IF EXISTS platform.ai_grid_phase_1_tenant_migration_audit CASCADE;
