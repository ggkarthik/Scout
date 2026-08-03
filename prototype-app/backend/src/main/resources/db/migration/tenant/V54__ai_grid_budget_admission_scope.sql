-- Preserve the scope dimensions used when a cadence admission is decided.
ALTER TABLE ai_grid_budget_admissions
    ADD COLUMN IF NOT EXISTS environment varchar(64) NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS criticality varchar(32) NOT NULL DEFAULT '*';

CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_admission_cadence
    ON ai_grid_budget_admissions (provider, environment, criticality, admitted_at DESC)
    WHERE decision = 'ADMITTED';
