-- Runtime execution identifiers are tenant-scoped HMAC digests, never provider plaintext.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ${tenantSchema}.ai_agent_executions)
       OR EXISTS (SELECT 1 FROM ${tenantSchema}.ai_agent_execution_cursors)
       OR EXISTS (SELECT 1 FROM ${tenantSchema}.ai_agent_execution_receipts) THEN
        RAISE EXCEPTION 'runtime metadata tables must be empty before the HMAC identity boundary is installed';
    END IF;
END $$;

ALTER TABLE ${tenantSchema}.ai_agent_executions
    RENAME COLUMN provider_execution_id TO provider_execution_digest;

ALTER TABLE ${tenantSchema}.ai_agent_execution_cursors
    RENAME COLUMN provider_stable_id TO provider_stable_digest;

ALTER TABLE ${tenantSchema}.ai_agent_executions
    ADD COLUMN IF NOT EXISTS digest_key_version varchar(64) NOT NULL DEFAULT 'v1';

ALTER TABLE ${tenantSchema}.ai_agent_executions
    DROP CONSTRAINT IF EXISTS ai_agent_executions_tenant_id_provider_provider_execution_id_key;

ALTER TABLE ${tenantSchema}.ai_agent_executions
    ADD CONSTRAINT ai_agent_executions_tenant_provider_execution_digest_key
        UNIQUE (tenant_id, provider, provider_execution_digest, digest_key_version);

CREATE INDEX IF NOT EXISTS idx_ai_agent_executions_source_time
    ON ${tenantSchema}.ai_agent_executions(source, evidence_time DESC);
