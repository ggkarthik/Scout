-- Add ServiceNow incident tracking columns to findings
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS incident_id     VARCHAR(64),
  ADD COLUMN IF NOT EXISTS incident_status VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_findings_incident_id ON findings (incident_id) WHERE incident_id IS NOT NULL;
