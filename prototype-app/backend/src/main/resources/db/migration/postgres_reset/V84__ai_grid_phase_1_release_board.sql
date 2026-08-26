-- migration-guard: platform-only
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_release_gate_evidence (
    id uuid PRIMARY KEY,
    gate_key varchar(64) NOT NULL,
    status varchar(16) NOT NULL,
    evidence_json jsonb NOT NULL,
    recorded_by varchar(255) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (gate_key IN ('CANARY_AWS','CANARY_AZURE','CANARY_MULTI_CLOUD','PERFORMANCE','ROLLBACK_AWS','ROLLBACK_AZURE','ROLLBACK_MULTI_CLOUD')),
    CHECK (status IN ('PASSED','FAILED'))
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_phase_1_release_gate_latest
    ON platform.ai_grid_phase_1_release_gate_evidence (gate_key, recorded_at DESC);
