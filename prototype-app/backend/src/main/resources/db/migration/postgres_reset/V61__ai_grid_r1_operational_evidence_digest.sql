-- migration-guard: platform-only
-- Operational release evidence is valid only for the connector/catalog material that produced it.
ALTER TABLE platform.ai_grid_release_gate_evidence
    ADD COLUMN material_digest varchar(64);

CREATE INDEX idx_ai_grid_release_gate_material
    ON platform.ai_grid_release_gate_evidence (release_id, gate_code, material_digest, recorded_at DESC);
