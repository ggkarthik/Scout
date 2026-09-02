-- migration-guard: platform-only
-- Pre-approval deployment to explicit development/test tenants.

ALTER TABLE platform.ai_grid_policy_distribution
    DROP CONSTRAINT IF EXISTS ai_grid_policy_distribution_rollout_stage_check;
ALTER TABLE platform.ai_grid_policy_distribution
    ADD CONSTRAINT ai_grid_policy_distribution_rollout_stage_check
    CHECK (rollout_stage IN ('GENERAL_AVAILABILITY','CANARY','DEV','PAUSED','RETIRED'));

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_dev_deployments (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    target_tenant_ids_json jsonb NOT NULL,
    test_note text NOT NULL,
    deployed_by varchar(255) NOT NULL,
    deployed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_dev_deployments_policy
    ON platform.ai_grid_policy_dev_deployments (policy_id, deployed_at DESC);
