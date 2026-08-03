-- migration-guard: platform-only
-- The generalized host Finding schema for tenant schemas is owned by the tenant migration line
-- (tenant V48, applied per schema by the tenant schema control plane). Platform migrations must not
-- issue tenant-table DDL (enforced by .github/scripts/check-tenant-ddl.py), so no findings DDL here.

CREATE TABLE platform.ai_grid_release_gate_evidence (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    gate_code varchar(96) NOT NULL,
    status varchar(16) NOT NULL,
    evidence_reference text NOT NULL,
    rationale text NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_by varchar(255) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (status IN ('PASS','FAIL')),
    CHECK (valid_until > recorded_at)
);

CREATE INDEX idx_ai_grid_release_gate_latest
    ON platform.ai_grid_release_gate_evidence (release_id, gate_code, recorded_at DESC);

CREATE TABLE platform.ai_grid_release_decisions (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    decision varchar(16) NOT NULL,
    gate_snapshot_json jsonb NOT NULL,
    reason text NOT NULL,
    decided_by varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (decision IN ('APPROVED','BLOCKED'))
);

CREATE INDEX idx_ai_grid_release_decision_latest
    ON platform.ai_grid_release_decisions (release_id, decided_at DESC);
