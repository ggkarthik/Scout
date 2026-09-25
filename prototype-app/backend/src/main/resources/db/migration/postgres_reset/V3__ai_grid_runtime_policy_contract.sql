-- migration-guard: platform-only

ALTER TABLE platform.ai_grid_runtime_field_definitions
    ADD COLUMN physical_column boolean NOT NULL DEFAULT true;

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT ai_grid_policy_evaluation_mode_check;

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_evaluation_mode_check
    CHECK (evaluation_mode IS NULL OR evaluation_mode IN (
        'ARTIFACT_FACTS',
        'DIRECT_RELATIONSHIP',
        'CORRELATION_PATH',
        'RUNTIME_FACTS',
        'RUNTIME_SEQUENCE',
        'RUNTIME_AGGREGATE'
        ,'RUNTIME_COVERAGE'
    ));

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT ai_grid_policy_evaluation_subject_check;

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_evaluation_subject_check
    CHECK (evaluation_subject IN
        ('ARTIFACT', 'RELATIONSHIP', 'SYSTEM', 'RESOURCE_CONFIGURATION', 'EXECUTION'));

-- Runtime evidence families. A runtime policy declares these so an unsupported provider
-- reports NOT_ASSESSED against a named capability rather than a silent pass.
INSERT INTO platform.ai_grid_resource_family_definitions
    (resource_family, provider, scope_semantics, lifecycle, description)
VALUES
    ('RUNTIME_EXECUTIONS', 'MULTI_CLOUD', 'ACCOUNT_GLOBAL', 'ACTIVE',
        'Bounded agent execution metadata collected from a provider connector or governed adapter.'),
    ('RUNTIME_EVENT_DECISIONS', 'MULTI_CLOUD', 'ACCOUNT_GLOBAL', 'ACTIVE',
        'Per-action approval, policy and outcome decisions recorded at event scope.'),
    ('RUNTIME_COMPONENT_USE', 'MULTI_CLOUD', 'ACCOUNT_GLOBAL', 'ACTIVE',
        'Observed tool, tool-version and target digests for a runtime action.'),
    ('RUNTIME_DATA_HANDLING', 'MULTI_CLOUD', 'ACCOUNT_GLOBAL', 'ACTIVE',
        'Data sensitivity and data operation classification for a runtime action.'),
    ('RUNTIME_AUTONOMY_CONTROLS', 'MULTI_CLOUD', 'ACCOUNT_GLOBAL', 'ACTIVE',
        'Handoff, memory, provenance and containment evidence for high-impact autonomy.')
ON CONFLICT (resource_family) DO NOTHING;

INSERT INTO platform.ai_grid_capability_definitions
    (capability_id, provider, connector, resource_family, optional, lifecycle, remediation)
VALUES
    ('RUNTIME_EXECUTION_METADATA', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_EXECUTIONS', false, 'ACTIVE',
        'Enable runtime collection for the provider connector, or register a governed telemetry adapter.'),
    ('RUNTIME_VERSION_CORRELATION', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_EXECUTIONS', false, 'ACTIVE',
        'Supply a stable provider agent-version key so executions can be correlated to a version.'),
    ('RUNTIME_EVENT_DECISIONS', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_EVENT_DECISIONS', false, 'ACTIVE',
        'Enable the provider decision source, or emit approval and policy state per action from an enforcement point.'),
    ('RUNTIME_ACTION_OUTCOMES', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_EVENT_DECISIONS', false, 'ACTIVE',
        'Emit the outcome of each consequential action so denials can be distinguished from completions.'),
    ('RUNTIME_TOOL_CORRELATION', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_COMPONENT_USE', false, 'ACTIVE',
        'Emit tool and tool-version digests so observed components can be matched to the allowlist.'),
    ('RUNTIME_DATA_CLASSIFICATION', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_DATA_HANDLING', false, 'ACTIVE',
        'Correlate runtime data operations to existing classification results without ingesting content.'),
    ('RUNTIME_HANDOFF_EVIDENCE', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_AUTONOMY_CONTROLS', true, 'ACTIVE',
        'No authoritative agent-to-agent handoff source exists yet; controls stay paused pending evidence.'),
    ('RUNTIME_MEMORY_EVIDENCE', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_AUTONOMY_CONTROLS', true, 'ACTIVE',
        'No authoritative durable-memory source exists yet; controls stay paused pending evidence.'),
    ('RUNTIME_PROVENANCE_EVIDENCE', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_AUTONOMY_CONTROLS', true, 'ACTIVE',
        'No authoritative tool or MCP provenance source exists yet; controls stay paused pending evidence.'),
    ('RUNTIME_CONTAINMENT_EVIDENCE', 'MULTI_CLOUD', 'AI_GRID_RUNTIME', 'RUNTIME_AUTONOMY_CONTROLS', true, 'ACTIVE',
        'No authoritative stop or containment control source exists yet; controls stay paused pending evidence.')
ON CONFLICT (capability_id) DO NOTHING;

INSERT INTO platform.ai_grid_runtime_field_definitions
    (field_key, source_table, source_column, value_type, predicate_eligible)
VALUES
    ('execution.source', 'ai_agent_executions', 'source', 'STRING', true),
    ('execution.agent_artifact_id', 'ai_agent_executions', 'agent_artifact_id', 'UUID', true),
    ('execution.agent_version_artifact_id', 'ai_agent_executions', 'agent_version_artifact_id', 'UUID', true),
    ('execution.environment_digest', 'ai_agent_executions', 'environment_digest', 'STRING', true),
    ('execution.deployment_digest', 'ai_agent_executions', 'deployment_digest', 'STRING', true),
    ('execution.acting_identity_digest', 'ai_agent_executions', 'acting_identity_digest', 'STRING', true),
    ('execution.delegated_identity_digest', 'ai_agent_executions', 'delegated_identity_digest', 'STRING', true),
    ('execution.provider_agent_version_digest', 'ai_agent_executions',
        'provider_agent_version_digest', 'STRING', true),
    ('execution.termination_reason', 'ai_agent_executions', 'termination_reason', 'STRING', true),
    ('execution.evidence_source', 'ai_agent_executions', 'evidence_source', 'STRING', true),
    ('execution.evidence_class', 'ai_agent_executions', 'evidence_class', 'STRING', true),
    ('execution.evidence_confidence', 'ai_agent_executions', 'evidence_confidence', 'NUMBER', true),
    ('execution.step_count', 'ai_agent_executions', 'step_count', 'NUMBER', true),
    ('execution.spend_currency', 'ai_agent_executions', 'spend_currency', 'STRING', true),
    ('execution.spend_unit', 'ai_agent_executions', 'spend_unit', 'STRING', true),
    ('execution.collected_at', 'ai_agent_executions', 'collected_at', 'TIMESTAMP', true),
    ('execution.provider_event_time', 'ai_agent_executions', 'provider_event_time', 'TIMESTAMP', true),
    ('execution.delivery_latency_ms', 'ai_agent_executions', 'delivery_latency_ms', 'NUMBER', true),
    ('execution.version_approval_state', 'ai_agent_executions', 'version_approval_state', 'STRING', true),
    ('execution.version_lifecycle_state', 'ai_agent_executions', 'version_lifecycle_state', 'STRING', true),
    ('event.action_category', 'ai_agent_execution_events', 'action_category', 'STRING', true),
    ('event.target_class', 'ai_agent_execution_events', 'target_class', 'STRING', true),
    ('event.tool_digest', 'ai_agent_execution_events', 'tool_digest', 'STRING', true),
    ('event.tool_version_digest', 'ai_agent_execution_events', 'tool_version_digest', 'STRING', true),
    ('event.target_digest', 'ai_agent_execution_events', 'target_digest', 'STRING', true),
    ('event.action_correlation_digest', 'ai_agent_execution_events', 'action_correlation_digest', 'STRING', true),
    ('event.data_sensitivity', 'ai_agent_execution_events', 'data_sensitivity', 'STRING', true),
    ('event.data_operation', 'ai_agent_execution_events', 'data_operation', 'STRING', true),
    ('event.approval_state', 'ai_agent_execution_events', 'approval_state', 'STRING', true),
    ('event.policy_state', 'ai_agent_execution_events', 'policy_state', 'STRING', true),
    ('event.decision_reason', 'ai_agent_execution_events', 'decision_reason', 'STRING', true),
    ('event.enforcement_point', 'ai_agent_execution_events', 'enforcement_point', 'STRING', true),
    ('event.action_outcome', 'ai_agent_execution_events', 'action_outcome', 'STRING', true),
    ('event.evidence_class', 'ai_agent_execution_events', 'evidence_class', 'STRING', true),
    ('event.component_approval_state', 'ai_agent_execution_events', 'component_approval_state', 'STRING', true),
    ('event.ingested_at', 'ai_agent_execution_events', 'ingested_at', 'TIMESTAMP', false)
ON CONFLICT (field_key) DO UPDATE SET
    source_table = excluded.source_table,
    source_column = excluded.source_column,
    value_type = excluded.value_type,
    predicate_eligible = excluded.predicate_eligible,
    lifecycle = 'ACTIVE';

UPDATE platform.ai_grid_runtime_field_definitions
   SET physical_column = false
 WHERE field_key IN (
    'execution.version_approval_state',
    'execution.version_lifecycle_state',
    'event.component_approval_state'
 );
