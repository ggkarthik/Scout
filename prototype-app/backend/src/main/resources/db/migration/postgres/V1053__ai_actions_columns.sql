-- Add AI required-actions columns to org_cve_records
ALTER TABLE org_cve_records
  ADD COLUMN IF NOT EXISTS ai_actions_json TEXT,
  ADD COLUMN IF NOT EXISTS ai_actions_generated_at TIMESTAMPTZ;
