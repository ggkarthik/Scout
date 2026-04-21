-- Add AI solution recommendation columns to org_cve_records
ALTER TABLE org_cve_records
  ADD COLUMN IF NOT EXISTS ai_solution_json TEXT,
  ADD COLUMN IF NOT EXISTS ai_solution_generated_at TIMESTAMPTZ;
