-- Postgres-safe incremental adoption migration for risk policy extension columns.

DO $$
BEGIN
  IF to_regclass('risk_policies') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_not_affected_freshness_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_fixed_freshness_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_known_affected_boost DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_under_investigation_penalty DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_not_affected_reduction DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS vex_stale_penalty DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS finding_generation_mode VARCHAR(20);
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_critical_risk_boost DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_high_risk_boost DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_medium_risk_boost DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_low_risk_boost DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS critical_sla_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS high_sla_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS medium_sla_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS low_sla_days INTEGER;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_critical_sla_multiplier DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_high_sla_multiplier DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_medium_sla_multiplier DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS asset_low_sla_multiplier DOUBLE PRECISION;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS auto_close_enabled BOOLEAN;
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS auto_close_asset_identifier VARCHAR(255);
  ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS auto_close_after_days INTEGER;

  UPDATE risk_policies
  SET
    vex_not_affected_freshness_days = COALESCE(vex_not_affected_freshness_days, 30),
    vex_fixed_freshness_days = COALESCE(vex_fixed_freshness_days, 30),
    vex_known_affected_boost = COALESCE(vex_known_affected_boost, 0.4),
    vex_under_investigation_penalty = COALESCE(vex_under_investigation_penalty, 0.2),
    vex_not_affected_reduction = COALESCE(vex_not_affected_reduction, 0.8),
    vex_stale_penalty = COALESCE(vex_stale_penalty, 0.5),
    finding_generation_mode = COALESCE(finding_generation_mode, 'MANUAL'),
    asset_critical_risk_boost = COALESCE(asset_critical_risk_boost, 1.5),
    asset_high_risk_boost = COALESCE(asset_high_risk_boost, 1.0),
    asset_medium_risk_boost = COALESCE(asset_medium_risk_boost, 0.5),
    asset_low_risk_boost = COALESCE(asset_low_risk_boost, 0.0),
    critical_sla_days = COALESCE(critical_sla_days, 7),
    high_sla_days = COALESCE(high_sla_days, 14),
    medium_sla_days = COALESCE(medium_sla_days, 30),
    low_sla_days = COALESCE(low_sla_days, 60),
    asset_critical_sla_multiplier = COALESCE(asset_critical_sla_multiplier, 0.5),
    asset_high_sla_multiplier = COALESCE(asset_high_sla_multiplier, 0.75),
    asset_medium_sla_multiplier = COALESCE(asset_medium_sla_multiplier, 1.0),
    asset_low_sla_multiplier = COALESCE(asset_low_sla_multiplier, 1.25),
    auto_close_enabled = COALESCE(auto_close_enabled, FALSE),
    auto_close_after_days = COALESCE(auto_close_after_days, 0);
END $$;
