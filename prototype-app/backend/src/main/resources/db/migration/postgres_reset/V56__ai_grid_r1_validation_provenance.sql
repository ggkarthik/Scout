-- migration-guard: platform-only
-- R1 answer-key runs must be tied to immutable tenant evidence, not caller-authored JSON alone.

ALTER TABLE platform.ai_grid_answer_key_runs
    ADD COLUMN source_tenant_id uuid REFERENCES platform.tenants(id),
    ADD COLUMN source_run_id uuid,
    ADD COLUMN provenance_state varchar(32) NOT NULL DEFAULT 'EXTERNAL_ATTESTATION';

ALTER TABLE platform.ai_grid_answer_key_runs
    ADD CONSTRAINT ai_grid_answer_key_run_provenance_state_check
    CHECK (provenance_state IN ('EXTERNAL_ATTESTATION','PLATFORM_RUN_BOUND'));

ALTER TABLE platform.ai_grid_answer_key_results
    ADD COLUMN source_assessment_id uuid,
    ADD COLUMN source_decision_fingerprint varchar(64);

CREATE INDEX idx_ai_grid_answer_key_run_source
    ON platform.ai_grid_answer_key_runs (source_tenant_id, source_run_id, completed_at DESC);

