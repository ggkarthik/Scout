-- migration-guard: platform-only
-- Phase 0 (AI Security) — entitlement resolution compatibility.
--
-- Correcting entitlement resolution precedence (active tenant override -> plan value ->
-- disabled default) means platform.plan_entitlements rows now actually drive runtime behavior,
-- where previously the resolver returned enabled=true unconditionally. The six existing ai.*
-- capabilities are already seeded enabled for PRO/ENTERPRISE/DEMO/PILOT by V27; this migration
-- re-asserts that seed idempotently so the compatibility guarantee lives inside the Phase 0
-- change set itself and does not depend on V27 having succeeded. ON CONFLICT DO NOTHING never
-- overrides an operator's deliberate value — any divergence surfaces through SHADOW-mode
-- mismatch telemetry for human review before ENFORCE cutover.
--
-- It also introduces the single AI Security pilot entitlement, ai.security, seeded DISABLED for
-- every plan. Per-tenant canary enablement is done through platform.tenant_entitlement_overrides,
-- not plan defaults. Connector and policy administration are gated by authorization roles, not by
-- additional entitlement keys.

-- 1. Defensive re-assert: keep the six existing AI capabilities enabled for supported plans.
INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, ed.key, true, NULL, now(), now()
FROM platform.plan_definitions pd
CROSS JOIN platform.entitlement_definitions ed
WHERE pd.code IN ('PRO', 'ENTERPRISE', 'DEMO', 'PILOT')
  AND ed.category = 'AI'
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;

-- 2. Introduce the AI Security pilot entitlement definition.
INSERT INTO platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at)
VALUES ('ai.security', 'AI_SECURITY', 'BOOLEAN',
        'Access the AI Security module (inventory, findings, policies)', now(), now())
ON CONFLICT (key) DO NOTHING;

-- 3. Seed ai.security DISABLED for every plan. Enablement is per-tenant via overrides (canary).
INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, 'ai.security', false, NULL, now(), now()
FROM platform.plan_definitions pd
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;
