-- RLS rollout gate.
--
-- Do not enable tenant RLS in the guardrail/background-fix rollout. RLS policy
-- creation, data validation, hot-path performance checks, and FORCE ROW LEVEL
-- SECURITY belong in the dedicated Phase 4 rollout migration once production
-- and preproduction runtime roles have been verified as non-superuser,
-- non-BYPASSRLS, and non-owner for protected tables.
SELECT 1;
