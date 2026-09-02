-- migration-guard: platform-only
-- Preserve the V91 rollout audit records, but prevent its automatically-created
-- tenant work from being claimed after package installation is separated from
-- publication and distribution.

ALTER TABLE platform.ai_grid_policy_rollouts
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollouts_status_check;
ALTER TABLE platform.ai_grid_policy_rollouts
    ADD CONSTRAINT ai_grid_policy_rollouts_status_check
    CHECK (status IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELLED'));

ALTER TABLE platform.ai_grid_policy_rollout_tasks
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollout_tasks_status_check;
ALTER TABLE platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_status_check
    CHECK (status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','COMPLETED','FAILED','CANCELLED'));

UPDATE platform.ai_grid_policy_rollout_tasks task
   SET status = 'CANCELLED',
       failure_detail = 'Cancelled: package installation does not authorize tenant rollout',
       next_retry_at = NULL,
       completed_at = now(),
       updated_at = now()
  FROM platform.ai_grid_policy_rollouts rollout
 WHERE task.rollout_id = rollout.id
   AND rollout.release_id = 'AGCF_PHASE_1_INITIAL'
   AND task.status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','FAILED');

UPDATE platform.ai_grid_policy_rollouts rollout
   SET status = 'CANCELLED', completed_at = now()
 WHERE rollout.release_id = 'AGCF_PHASE_1_INITIAL'
   AND status <> 'COMPLETED';
