-- Restore the entitlement seed data that was lost when the original entitlements migration was
-- dropped from the migration set. The platform.entitlement_definitions and platform.plan_entitlements
-- tables are created in V1; this migration populates them.
--
-- It runs after V18 (which seeds platform.plan_definitions), so the plan_code foreign keys resolve,
-- and is fully idempotent (ON CONFLICT DO NOTHING) so databases that already hold this data — every
-- existing deployment — are unaffected. On a fresh database this makes the AI entitlements available
-- for all plans, matching production, so V24__enable_investigation_agent_all_plans.sql has rows to act on.

INSERT INTO platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at)
VALUES
    ('ai.investigation_summary',  'AI', 'BOOLEAN', 'Generate AI investigation summaries', now(), now()),
    ('ai.solution_generation',    'AI', 'BOOLEAN', 'Generate AI remediation solutions', now(), now()),
    ('ai.required_actions',       'AI', 'BOOLEAN', 'Generate AI required actions', now(), now()),
    ('ai.fix_generation',         'AI', 'BOOLEAN', 'Generate AI fix records', now(), now()),
    ('ai.upgrade_recommendation', 'AI', 'BOOLEAN', 'Generate AI upgrade recommendations', now(), now()),
    ('ai.investigation_agent',    'AI', 'BOOLEAN', 'Run AI investigation agent workflows', now(), now())
ON CONFLICT (key) DO NOTHING;

INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, ed.key, true, NULL, now(), now()
FROM platform.plan_definitions pd
CROSS JOIN platform.entitlement_definitions ed
WHERE pd.code IN ('PRO', 'ENTERPRISE', 'DEMO', 'PILOT')
  AND ed.category = 'AI'
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;
