ALTER TABLE ai_grid_host_context_facts
    ADD COLUMN IF NOT EXISTS producer_id varchar(128) NOT NULL DEFAULT 'LEGACY_UNBOUND';

CREATE INDEX IF NOT EXISTS idx_ai_grid_host_context_producer
    ON ai_grid_host_context_facts (producer_id, confidence_method_version, observed_at DESC);
