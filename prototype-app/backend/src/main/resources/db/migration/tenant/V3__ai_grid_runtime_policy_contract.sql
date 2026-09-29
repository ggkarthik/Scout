-- migration-guard: tenant-only

ALTER TABLE ${tenantSchema}.ai_grid_assessments
    DROP CONSTRAINT ai_grid_assessments_tenant_id_run_id_policy_id_subject_type_key;

ALTER TABLE ${tenantSchema}.ai_grid_assessments
    ADD CONSTRAINT uq_ai_grid_assessments_evaluation_identity
    UNIQUE (tenant_id, run_id, policy_id, subject_type, subject_id, fingerprint);

ALTER TABLE ${tenantSchema}.ai_agent_executions
    ADD COLUMN environment_digest varchar(256),
    ADD COLUMN deployment_digest varchar(256),
    ADD COLUMN acting_identity_digest varchar(256),
    ADD COLUMN delegated_identity_digest varchar(256),
    ADD COLUMN identity_digest_key_version varchar(64),
    ADD COLUMN termination_reason varchar(128),
    ADD COLUMN evidence_source varchar(128),
    ADD COLUMN evidence_class varchar(64),
    ADD COLUMN evidence_confidence numeric(5,4),
    ADD COLUMN step_count bigint,
    ADD COLUMN spend_currency varchar(16),
    ADD COLUMN spend_unit varchar(32),
    ADD COLUMN collected_at timestamptz,
    ADD COLUMN provider_event_time timestamptz,
    ADD COLUMN delivery_latency_ms bigint,
    ADD CONSTRAINT ai_agent_executions_evidence_confidence_check
        CHECK (evidence_confidence IS NULL OR (evidence_confidence >= 0 AND evidence_confidence <= 1)),
    ADD CONSTRAINT ai_agent_executions_step_count_check
        CHECK (step_count IS NULL OR step_count >= 0),
    ADD CONSTRAINT ai_agent_executions_delivery_latency_check
        CHECK (delivery_latency_ms IS NULL OR delivery_latency_ms >= 0);

-- Governed telemetry adapters are not connector-backed. Their source and producer registration
-- provide the trust boundary, so their execution receipts do not carry a connector identifier.
ALTER TABLE ${tenantSchema}.ai_agent_execution_receipts
    ALTER COLUMN connector_id DROP NOT NULL;

ALTER TABLE ${tenantSchema}.ai_agent_execution_events
    ADD COLUMN producer_id varchar(128),
    ADD COLUMN provider_event_digest varchar(256),
    ADD COLUMN digest_key_version varchar(64),
    ADD COLUMN ingested_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN action_category varchar(32),
    ADD COLUMN target_class varchar(32),
    ADD COLUMN tool_digest varchar(256),
    ADD COLUMN tool_version_digest varchar(256),
    ADD COLUMN target_digest varchar(256),
    ADD COLUMN action_correlation_digest varchar(256),
    ADD COLUMN data_sensitivity varchar(64),
    ADD COLUMN data_operation varchar(64),
    ADD COLUMN approval_state varchar(64),
    ADD COLUMN policy_state varchar(64),
    ADD COLUMN decision_reason varchar(512),
    ADD COLUMN enforcement_point varchar(128),
    ADD COLUMN action_outcome varchar(64),
    ADD COLUMN evidence_class varchar(64),
    ADD CONSTRAINT ai_agent_execution_events_action_category_check
        CHECK (action_category IS NULL OR action_category IN
            ('READ','WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH','OTHER')),
    ADD CONSTRAINT ai_agent_execution_events_target_class_check
        CHECK (target_class IS NULL OR target_class IN
            ('INTERNAL','EXTERNAL','PUBLIC','SENSITIVE_STORE','CODE_RUNTIME','IDENTITY_SYSTEM',
             'FINANCIAL_SYSTEM','UNKNOWN')),
    ADD CONSTRAINT ai_agent_execution_events_approval_state_check
        CHECK (approval_state IS NULL OR approval_state IN
            ('APPROVED','DENIED','REQUIRED','NOT_REQUIRED','BYPASSED','UNKNOWN')),
    ADD CONSTRAINT ai_agent_execution_events_policy_state_check
        CHECK (policy_state IS NULL OR policy_state IN
            ('ALLOWED','DENIED','BLOCKED','NOT_EVALUATED','UNKNOWN')),
    ADD CONSTRAINT ai_agent_execution_events_action_outcome_check
        CHECK (action_outcome IS NULL OR action_outcome IN
            ('SUCCEEDED','FAILED','DENIED','BLOCKED','CANCELLED','UNKNOWN')),
    ADD CONSTRAINT ai_agent_execution_events_data_sensitivity_check
        CHECK (data_sensitivity IS NULL OR data_sensitivity IN
            ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','UNKNOWN')),
    ADD CONSTRAINT ai_agent_execution_events_data_operation_check
        CHECK (data_operation IS NULL OR data_operation IN
            ('READ','WRITE','DELETE','TRANSFORM','TRANSMIT','NONE','UNKNOWN'));

CREATE UNIQUE INDEX uq_ai_agent_execution_events_provider_event
    ON ${tenantSchema}.ai_agent_execution_events
        (tenant_id, producer_id, provider_event_digest, digest_key_version)
    WHERE producer_id IS NOT NULL AND provider_event_digest IS NOT NULL AND digest_key_version IS NOT NULL;

CREATE INDEX idx_ai_agent_execution_events_consequential_time
    ON ${tenantSchema}.ai_agent_execution_events(tenant_id, event_time DESC, action_category)
    WHERE action_category IN ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH');

CREATE TABLE ${tenantSchema}.ai_runtime_evidence_producers (
    producer_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    service_account_id uuid NOT NULL REFERENCES ${tenantSchema}.service_accounts(id),
    provider varchar(64) NOT NULL,
    producer_type varchar(64) NOT NULL,
    submitted_evidence_class varchar(64) NOT NULL,
    certification_state varchar(32) NOT NULL DEFAULT 'UNCERTIFIED',
    certified_evidence_families_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_runtime_evidence_producer_type_check
        CHECK (producer_type IN ('RUNTIME_EVIDENCE_PRODUCER')),
    CONSTRAINT ai_runtime_evidence_producer_certification_check
        CHECK (certification_state IN ('UNCERTIFIED','CERTIFIED','REVOKED')),
    CONSTRAINT ai_runtime_evidence_producer_status_check
        CHECK (status IN ('ACTIVE','INACTIVE','REVOKED')),
    CONSTRAINT ai_runtime_evidence_producer_families_check
        CHECK (jsonb_typeof(certified_evidence_families_json) = 'array')
);

CREATE TABLE ${tenantSchema}.ai_runtime_source_configurations (
    source_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    provider varchar(64) NOT NULL,
    source_kind varchar(32) NOT NULL,
    feature_key varchar(128),
    required_for_program_gate boolean NOT NULL DEFAULT false,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_runtime_source_kind_check
        CHECK (source_kind IN ('PROVIDER_CONNECTOR','TELEMETRY_ADAPTER')),
    CONSTRAINT ai_runtime_source_status_check
        CHECK (status IN ('ACTIVE','INACTIVE'))
);

INSERT INTO ${tenantSchema}.ai_runtime_source_configurations
    (source_id, tenant_id, provider, source_kind, feature_key, required_for_program_gate, status)
VALUES
    ('AZURE_FOUNDRY_RUNTIME', '${tenantId}'::uuid, 'AZURE_FOUNDRY',
        'PROVIDER_CONNECTOR', 'AZURE_FOUNDRY_RUNTIME', true, 'ACTIVE'),
    ('COPILOT_STUDIO_RUNTIME', '${tenantId}'::uuid, 'MICROSOFT_COPILOT',
        'PROVIDER_CONNECTOR', 'COPILOT_RUNTIME', true, 'ACTIVE')
ON CONFLICT (source_id) DO NOTHING;

ALTER TABLE ${tenantSchema}.ai_grid_budget_config
    ADD COLUMN runtime_quota_window_seconds bigint NOT NULL DEFAULT 86400,
    ADD COLUMN rolling_runtime_event_limit bigint,
    ADD COLUMN rolling_runtime_byte_limit bigint,
    ADD CONSTRAINT ai_grid_budget_runtime_window_check
        CHECK (runtime_quota_window_seconds > 0),
    ADD CONSTRAINT ai_grid_budget_runtime_event_limit_check
        CHECK (rolling_runtime_event_limit IS NULL OR rolling_runtime_event_limit > 0),
    ADD CONSTRAINT ai_grid_budget_runtime_byte_limit_check
        CHECK (rolling_runtime_byte_limit IS NULL OR rolling_runtime_byte_limit > 0);

CREATE TABLE ${tenantSchema}.ai_runtime_quota_windows (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    source_id varchar(128) NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    accepted_event_count bigint NOT NULL DEFAULT 0,
    accepted_byte_count bigint NOT NULL DEFAULT 0,
    rejected_event_count bigint NOT NULL DEFAULT 0,
    rejected_byte_count bigint NOT NULL DEFAULT 0,
    quota_state varchar(32) NOT NULL DEFAULT 'AVAILABLE',
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_id, window_start),
    CONSTRAINT ai_runtime_quota_window_bounds_check CHECK (window_end > window_start),
    CONSTRAINT ai_runtime_quota_counts_check CHECK (
        accepted_event_count >= 0 AND accepted_byte_count >= 0
        AND rejected_event_count >= 0 AND rejected_byte_count >= 0),
    CONSTRAINT ai_runtime_quota_state_check
        CHECK (quota_state IN ('AVAILABLE','SOFT_LIMIT','EXHAUSTED'))
);

CREATE TABLE ${tenantSchema}.ai_runtime_ingestion_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    producer_id varchar(128) NOT NULL REFERENCES ${tenantSchema}.ai_runtime_evidence_producers(producer_id),
    status varchar(32) NOT NULL,
    accepted_count integer NOT NULL DEFAULT 0,
    duplicate_count integer NOT NULL DEFAULT 0,
    quarantined_count integer NOT NULL DEFAULT 0,
    reason_code varchar(128),
    ingestion_job_id uuid,
    request_byte_count bigint NOT NULL DEFAULT 0,
    request_event_count bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT ai_runtime_ingestion_receipt_status_check
        CHECK (status IN ('ACCEPTED','PROCESSING','COMPLETED','REJECTED','FAILED')),
    CONSTRAINT ai_runtime_ingestion_receipt_counts_check
        CHECK (accepted_count >= 0 AND duplicate_count >= 0 AND quarantined_count >= 0
            AND request_byte_count >= 0 AND request_event_count >= 0)
);

-- Runtime policy failures are a distinct finding kind from posture and exposure. The
-- execution subject has no owning artifact, so the kind must be addressable before the
-- runtime evaluator can reconcile its first FAIL.
ALTER TABLE ${tenantSchema}.findings
    DROP CONSTRAINT findings_kind_check;

ALTER TABLE ${tenantSchema}.findings
    ADD CONSTRAINT findings_kind_check
    CHECK (finding_kind IN ('VULNERABILITY', 'AI_POSTURE', 'AI_EXPOSURE', 'AI_RUNTIME'));

ALTER TABLE ${tenantSchema}.ai_runtime_evidence_producers ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_runtime_evidence_producers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_runtime_evidence_producers
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ai_runtime_source_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_runtime_source_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_runtime_source_configurations
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ai_runtime_quota_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_runtime_quota_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_runtime_quota_windows
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ai_runtime_ingestion_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_runtime_ingestion_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_runtime_ingestion_receipts
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
