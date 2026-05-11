-- V1081: Drop obsolete vulnerability-scoring columns from risk_policies.
-- These fields (CVSS weight, EPSS weight, KEV boost, VEX modifiers, asset risk boosts)
-- are no longer used now that finding risk_score is derived exclusively from
-- findings_score_config via FindingsScoreService.

ALTER TABLE risk_policies
    DROP COLUMN IF EXISTS cvss_weight,
    DROP COLUMN IF EXISTS kev_boost,
    DROP COLUMN IF EXISTS epss_weight,
    DROP COLUMN IF EXISTS vex_not_affected_freshness_days,
    DROP COLUMN IF EXISTS vex_fixed_freshness_days,
    DROP COLUMN IF EXISTS vex_known_affected_boost,
    DROP COLUMN IF EXISTS vex_under_investigation_penalty,
    DROP COLUMN IF EXISTS vex_not_affected_reduction,
    DROP COLUMN IF EXISTS vex_stale_penalty,
    DROP COLUMN IF EXISTS asset_critical_risk_boost,
    DROP COLUMN IF EXISTS asset_high_risk_boost,
    DROP COLUMN IF EXISTS asset_medium_risk_boost,
    DROP COLUMN IF EXISTS asset_low_risk_boost;
