-- Microsoft connector gap-closure plumbing. Behaviour remains disabled until source gates pass.
CREATE TABLE ${tenantSchema}.ai_agent_executions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    provider varchar(64) NOT NULL,
    provider_execution_id varchar(512) NOT NULL,
    agent_artifact_id uuid REFERENCES ${tenantSchema}.ai_security_artifacts(id),
    source varchar(64) NOT NULL,
    started_at timestamptz,
    completed_at timestamptz,
    status varchar(32) NOT NULL,
    outcome_category varchar(64),
    approval_state varchar(64),
    policy_state varchar(64),
    classification varchar(64),
    api_version varchar(64),
    token_count bigint,
    latency_ms bigint,
    retry_count integer,
    spend_micros bigint,
    evidence_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, provider_execution_id)
);
CREATE INDEX idx_ai_agent_executions_agent_time ON ${tenantSchema}.ai_agent_executions(agent_artifact_id, evidence_time DESC);

CREATE TABLE ${tenantSchema}.ai_agent_execution_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    execution_id uuid NOT NULL REFERENCES ${tenantSchema}.ai_agent_executions(id) ON DELETE CASCADE,
    sequence bigint NOT NULL,
    event_time timestamptz NOT NULL,
    event_type varchar(64) NOT NULL,
    status varchar(32),
    classification varchar(64),
    evidence_time timestamptz NOT NULL,
    UNIQUE (tenant_id, execution_id, sequence)
);

CREATE TABLE ${tenantSchema}.ai_agent_execution_cursors (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    connector_id uuid NOT NULL,
    source varchar(64) NOT NULL,
    scope_key varchar(512) NOT NULL,
    provider_timestamp timestamptz,
    provider_stable_id varchar(512),
    lookback_days integer NOT NULL DEFAULT 30,
    overlap_days integer NOT NULL DEFAULT 3,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, connector_id, source, scope_key)
);

CREATE TABLE ${tenantSchema}.ai_agent_execution_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    connector_id uuid NOT NULL,
    source varchar(64) NOT NULL,
    scope_key varchar(512) NOT NULL,
    idempotency_key varchar(512) NOT NULL,
    content_hash varchar(128) NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE ${tenantSchema}.ai_security_connector_feature_flags (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    feature_key varchar(128) NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    kill_switch boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, feature_key)
);

ALTER TABLE ${tenantSchema}.ai_agent_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_connector_feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_executions FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_cursors FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_execution_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_connector_feature_flags FORCE ROW LEVEL SECURITY;
