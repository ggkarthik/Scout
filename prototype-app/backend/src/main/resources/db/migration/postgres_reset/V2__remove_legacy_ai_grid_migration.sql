-- migration-guard: platform-only
-- Retire the one-time detector migration.  This list is generated from a clean V1
-- platform.ai_grid_policy_migration_ledger and must remain an exact set match.
DO $$
DECLARE
    legacy_ids text[] := ARRAY['AWS_BEDROCK_WEAK_GUARDRAIL'];
BEGIN
    IF EXISTS (
        SELECT 1 FROM platform.ai_grid_policy_rollout_tasks t
        JOIN platform.ai_grid_policy_rollouts r ON r.id = t.rollout_id
        WHERE r.policy_id = ANY (legacy_ids) AND t.status = 'PROCESSING'
    ) OR EXISTS (
        SELECT 1 FROM platform.ai_grid_policy_deprecation_tasks t
        JOIN platform.ai_grid_policy_deprecations d ON d.id = t.deprecation_id
        WHERE d.policy_id = ANY (legacy_ids) AND t.state = 'PROCESSING'
    ) OR EXISTS (
        SELECT 1 FROM platform.ai_grid_policy_inactivation_tasks
        WHERE policy_id = ANY (legacy_ids) AND status = 'PROCESSING'
    ) THEN
        RAISE EXCEPTION 'AI Grid legacy cleanup cannot run while a legacy task is PROCESSING';
    END IF;

    -- Cancel retriable work before removing all historical task states below.
    UPDATE platform.ai_grid_policy_rollout_tasks t SET status='CANCELLED', completed_at=now(), updated_at=now(),
           failure_detail='Cancelled by legacy AI Grid cleanup'
      FROM platform.ai_grid_policy_rollouts r
     WHERE r.id=t.rollout_id AND r.policy_id = ANY (legacy_ids) AND t.status IN ('PENDING','FAILED','WAITING_FOR_SNAPSHOT');
    UPDATE platform.ai_grid_policy_deprecation_tasks t SET state='CANCELLED', completed_at=now(), updated_at=now(),
           failure_detail='Cancelled by legacy AI Grid cleanup'
      FROM platform.ai_grid_policy_deprecations d
     WHERE d.id=t.deprecation_id AND d.policy_id = ANY (legacy_ids) AND t.state IN ('PENDING','FAILED');
    UPDATE platform.ai_grid_policy_inactivation_tasks SET status='CANCELED', completed_at=now(), updated_at=now(),
           failure_detail='Cancelled by legacy AI Grid cleanup'
     WHERE policy_id = ANY (legacy_ids) AND status IN ('PENDING','FAILED');

    DELETE FROM platform.ai_grid_policy_rollout_tasks t USING platform.ai_grid_policy_rollouts r
     WHERE r.id=t.rollout_id AND r.policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_rollouts WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_deprecation_tasks t USING platform.ai_grid_policy_deprecations d
     WHERE d.id=t.deprecation_id AND d.policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_deprecations WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_inactivation_tasks WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_release_bindings WHERE policy_id = ANY (legacy_ids);
    ALTER TABLE platform.ai_grid_policy_release_decisions DISABLE TRIGGER ai_grid_policy_release_decisions_immutable;
    DELETE FROM platform.ai_grid_policy_release_decisions WHERE policy_id = ANY (legacy_ids);
    ALTER TABLE platform.ai_grid_policy_release_decisions ENABLE TRIGGER ai_grid_policy_release_decisions_immutable;
    DELETE FROM platform.ai_grid_policy_dev_deployments WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_distribution WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_policy_versions WHERE policy_id = ANY (legacy_ids);
    DELETE FROM platform.ai_grid_phase_1_tenant_migration_audit;
    DROP TABLE platform.ai_grid_phase_1_tenant_migration_audit;
    DROP TABLE platform.ai_grid_policy_migration_ledger;
END $$;
