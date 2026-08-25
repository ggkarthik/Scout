-- migration-guard: platform-only
-- New precision samples must be traceable to an immutable tenant assessment/run. Existing
-- historical samples remain readable but are explicitly legacy-unbound and cannot pass a current gate.
ALTER TABLE platform.ai_grid_precision_samples
    ADD COLUMN IF NOT EXISTS source_tenant_id uuid REFERENCES platform.tenants(id),
    ADD COLUMN IF NOT EXISTS source_run_id uuid,
    ADD COLUMN IF NOT EXISTS source_assessment_id uuid,
    ADD COLUMN IF NOT EXISTS source_decision_fingerprint varchar(128),
    ADD COLUMN IF NOT EXISTS provenance_state varchar(32) NOT NULL DEFAULT 'LEGACY_UNBOUND';

ALTER TABLE platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_sample_provenance_state_chk
    CHECK (provenance_state IN ('PLATFORM_RUN_BOUND', 'LEGACY_UNBOUND'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_grid_precision_sample_source_assessment
    ON platform.ai_grid_precision_samples (review_id, source_assessment_id)
    WHERE source_assessment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_grid_precision_sample_source_run
    ON platform.ai_grid_precision_samples (source_tenant_id, source_run_id, source_assessment_id);
