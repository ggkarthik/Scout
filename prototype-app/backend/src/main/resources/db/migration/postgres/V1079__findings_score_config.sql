ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS findings_score_config JSONB DEFAULT '[]';
