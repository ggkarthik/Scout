-- Preserve pre-AI-Grid tenant choices during the staged policy migration.
-- A governed selection always wins if it already exists.
INSERT INTO ai_grid_policy_selections (policy_id, tenant_id, selection, updated_by, reason)
SELECT legacy.policy_id,
       legacy.tenant_id,
       CASE WHEN published.default_selection = 'REQUIRED' THEN 'REQUIRED'
            WHEN legacy.enabled THEN 'ENABLED' ELSE 'DISABLED' END,
       legacy.updated_by,
       'Migrated from legacy ai_security_policy_settings'
  FROM ai_security_policy_settings legacy
  JOIN (
      SELECT DISTINCT ON (policy_id) policy_id, default_selection
        FROM platform.ai_grid_policy_versions
       WHERE lifecycle = 'PUBLISHED'
       ORDER BY policy_id, published_at DESC NULLS LAST, version DESC
  ) published ON published.policy_id = legacy.policy_id
ON CONFLICT (policy_id) DO NOTHING;
