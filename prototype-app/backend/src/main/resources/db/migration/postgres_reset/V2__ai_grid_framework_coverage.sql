-- migration-guard: platform-only

CREATE OR REPLACE FUNCTION platform.ai_grid_policy_visible_to_tenant(
    policy_available boolean,
    policy_rollout_stage varchar,
    policy_canary_tenant_ids jsonb,
    requested_tenant_id uuid
) RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
RETURN coalesce(policy_available, false)
   AND (
       policy_rollout_stage = 'GENERAL_AVAILABILITY'
       OR (
           policy_rollout_stage IN ('CANARY', 'DEV')
           AND coalesce(policy_canary_tenant_ids, '[]'::jsonb) ? requested_tenant_id::text
       )
   );

CREATE TABLE platform.ai_grid_frameworks (
    framework_key varchar(128) NOT NULL,
    framework_version varchar(32) NOT NULL,
    display_name varchar(255) NOT NULL,
    reporting_kind varchar(32) NOT NULL DEFAULT 'RISK_COVERAGE',
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (framework_key, framework_version),
    CONSTRAINT ai_grid_framework_reporting_kind_check
        CHECK (reporting_kind IN ('RISK_COVERAGE', 'CONTROL_MAPPING')),
    CONSTRAINT ai_grid_framework_lifecycle_check
        CHECK (lifecycle IN ('ACTIVE', 'RETIRED'))
);

CREATE TABLE platform.ai_grid_framework_controls (
    framework_key varchar(128) NOT NULL,
    framework_version varchar(32) NOT NULL,
    control_id varchar(64) NOT NULL,
    display_order integer NOT NULL,
    name varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (framework_key, framework_version, control_id),
    FOREIGN KEY (framework_key, framework_version)
        REFERENCES platform.ai_grid_frameworks(framework_key, framework_version) ON DELETE CASCADE,
    UNIQUE (framework_key, framework_version, display_order)
);

-- Runtime predicates may bind only to this typed contract. Diagnostic/extension JSON is
-- deliberately absent, so it cannot become a policy input under deadline pressure.
CREATE TABLE platform.ai_grid_runtime_field_definitions (
    field_key varchar(128) PRIMARY KEY,
    source_table varchar(128) NOT NULL,
    source_column varchar(128) NOT NULL,
    value_type varchar(32) NOT NULL,
    predicate_eligible boolean NOT NULL DEFAULT true,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE',
    UNIQUE (source_table, source_column),
    CONSTRAINT ai_grid_runtime_field_value_type_check
        CHECK (value_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'TIMESTAMP', 'UUID')),
    CONSTRAINT ai_grid_runtime_field_lifecycle_check
        CHECK (lifecycle IN ('ACTIVE', 'RETIRED'))
);

INSERT INTO platform.ai_grid_runtime_field_definitions
    (field_key, source_table, source_column, value_type, predicate_eligible)
VALUES
    ('execution.provider', 'ai_agent_executions', 'provider', 'STRING', true),
    ('execution.started_at', 'ai_agent_executions', 'started_at', 'TIMESTAMP', true),
    ('execution.completed_at', 'ai_agent_executions', 'completed_at', 'TIMESTAMP', true),
    ('execution.status', 'ai_agent_executions', 'status', 'STRING', true),
    ('execution.outcome_category', 'ai_agent_executions', 'outcome_category', 'STRING', true),
    ('execution.approval_state', 'ai_agent_executions', 'approval_state', 'STRING', true),
    ('execution.policy_state', 'ai_agent_executions', 'policy_state', 'STRING', true),
    ('execution.classification', 'ai_agent_executions', 'classification', 'STRING', true),
    ('execution.token_count', 'ai_agent_executions', 'token_count', 'NUMBER', true),
    ('execution.latency_ms', 'ai_agent_executions', 'latency_ms', 'NUMBER', true),
    ('execution.retry_count', 'ai_agent_executions', 'retry_count', 'NUMBER', true),
    ('execution.spend_micros', 'ai_agent_executions', 'spend_micros', 'NUMBER', true),
    ('execution.evidence_time', 'ai_agent_executions', 'evidence_time', 'TIMESTAMP', true),
    ('execution.correlation_status', 'ai_agent_executions', 'correlation_status', 'STRING', true),
    ('event.sequence', 'ai_agent_execution_events', 'sequence', 'NUMBER', true),
    ('event.event_time', 'ai_agent_execution_events', 'event_time', 'TIMESTAMP', true),
    ('event.event_type', 'ai_agent_execution_events', 'event_type', 'STRING', true),
    ('event.status', 'ai_agent_execution_events', 'status', 'STRING', true),
    ('event.classification', 'ai_agent_execution_events', 'classification', 'STRING', true),
    ('event.evidence_time', 'ai_agent_execution_events', 'evidence_time', 'TIMESTAMP', true)
ON CONFLICT (field_key) DO NOTHING;

INSERT INTO platform.ai_grid_frameworks
    (framework_key, framework_version, display_name, reporting_kind)
VALUES
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'OWASP GenAI LLM Top 10', 'RISK_COVERAGE'),
    ('CSA_AICM', '1.1', 'CSA AI Controls Matrix', 'CONTROL_MAPPING'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'OWASP Top 10 for Agentic Applications', 'RISK_COVERAGE')
ON CONFLICT (framework_key, framework_version) DO NOTHING;

INSERT INTO platform.ai_grid_framework_controls
    (framework_key, framework_version, control_id, display_order, name)
VALUES
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM01', 1, 'Prompt Injection'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM02', 2, 'Sensitive Information Disclosure'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM03', 3, 'Supply Chain'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM04', 4, 'Data and Model Poisoning'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM05', 5, 'Improper Output Handling'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM06', 6, 'Excessive Agency'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM07', 7, 'System Prompt Leakage'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM08', 8, 'Vector and Embedding Weaknesses'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM09', 9, 'Misinformation'),
    ('OWASP_GENAI_LLM_TOP_10', '2026', 'LLM10', 10, 'Unbounded Consumption'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI01', 1, 'Agent Goal Hijack'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI02', 2, 'Tool Misuse and Exploitation'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI03', 3, 'Identity and Privilege Abuse'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI04', 4, 'Agentic Supply Chain Vulnerabilities'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI05', 5, 'Unexpected Code Execution'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI06', 6, 'Memory and Context Poisoning'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI07', 7, 'Insecure Inter-Agent Communication'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI08', 8, 'Cascading Failures'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI09', 9, 'Human-Agent Trust Exploitation'),
    ('OWASP_AGENTIC_TOP_10', '2026', 'ASI10', 10, 'Rogue Agents')
ON CONFLICT (framework_key, framework_version, control_id) DO NOTHING;

INSERT INTO platform.ai_grid_framework_controls
    (framework_key, framework_version, control_id, display_order, name)
SELECT 'CSA_AICM', '1.1', control_id, ordinal, control_id
  FROM unnest(ARRAY[
      'AIS-08','AIS-09','AIS-10','AIS-11','AIS-13','BCR-03','CCC-06','CEK-03','CEK-08',
      'DCS-06','DCS-07','DSP-02','DSP-03','DSP-04','DSP-05','DSP-06','DSP-16','DSP-17',
      'DSP-20','DSP-23','GRC-02','GRC-06','GRC-09','GRC-13','I&S-02','I&S-03','I&S-06',
      'IAM-03','IAM-05','IAM-09','IAM-10','IAM-13','IAM-15','IAM-16','IAM-18','LOG-02',
      'LOG-03','LOG-07','LOG-09','LOG-14','LOG-15','LOG-16','MDS-01','MDS-02','MDS-08',
      'MDS-09','MDS-11','MDS-12','STA-08','STA-10','TVM-06','TVM-13'
  ]) WITH ORDINALITY controls(control_id, ordinal)
ON CONFLICT (framework_key, framework_version, control_id) DO NOTHING;
