-- migration-guard: platform-only
-- The three Phase 1 correlation definitions that complement the three retained R2 definitions.
INSERT INTO platform.ai_grid_correlation_versions
    (correlation_id,version,name,description,lifecycle,severity,precision_threshold,
     max_path_depth,max_fan_out,allowed_node_types_json,allowed_edge_types_json,
     requirements_json,approved_by,approved_at,published_at)
VALUES
('R2_EXTERNAL_MCP_SENSITIVE_ACCESS','1.0.0','External or unapproved MCP path to sensitive data',
 'An MCP server that is externally reachable or unapproved is connected to an AI path with confirmed sensitive-data access.',
 'PUBLISHED','CRITICAL',0.95,6,100,
 '["AI_AGENT","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["EXPOSES_MCP","CONNECTS_TO_MCP","CONTAINS_MCP_TARGET","USES_DATA_SOURCE","USES_SEARCH_INDEX","READS_FROM_S3"]',
 '{"validated":["mcp.external_or_unapproved_verified","data.sensitive_access_confirmed"],"hypothesis":["mcp.configured_auth_type","mcp.inbound_auth_type","mcp.outbound_auth_type","data.source_linked"]}',
 'ai-grid-phase-1',now(),now()),
('R2_MCP_WEAK_AUTH_EXECUTION','1.0.0','High-impact execution through an MCP target with weak authentication',
 'An autonomous or high-impact AI agent routes through an MCP target whose authentication is absent or unknown.',
 'PUBLISHED','HIGH',0.93,6,100,
 '["AI_AGENT","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","EXPOSES_MCP","CONNECTS_TO_MCP","CONTAINS_MCP_TARGET","INVOKES_LAMBDA"]',
 '{"validated":["agent.autonomous_execution_verified","mcp.auth_inadequate_verified"],"hypothesis":["agent.code_interpreter_enabled_configured","mcp.configured_auth_type","mcp.inbound_auth_type","mcp.outbound_auth_type"]}',
 'ai-grid-phase-1',now(),now()),
('R2_SENSITIVE_RETRIEVAL_CONTROL_GAP','1.0.0','Sensitive retrieval path without required guardrail or PII baseline',
 'An agent can retrieve sensitive data while the required guardrail or PII-filter baseline is absent.',
 'PUBLISHED','HIGH',0.92,6,100,
 '["AI_AGENT","AI_GUARDRAIL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","USES_SEARCH_INDEX","USES_GUARDRAIL","READS_FROM_S3"]',
 '{"validated":["data.sensitive_access_confirmed","control.execution_boundary_inadequate_verified"],"hypothesis":["data.source_linked","bedrock.agent.guardrail_attached_configured","bedrock.guardrail.minimum_strength_configured","guardrail.rai_non_blocking_filter_observed"]}',
 'ai-grid-phase-1',now(),now())
ON CONFLICT (correlation_id,version) DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,
     allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('mcp.external_or_unapproved_verified','1.0.0','BOOLEAN',
 'Approved graph or runtime evidence verifies that an MCP endpoint is external or unapproved.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('mcp.auth_inadequate_verified','1.0.0','BOOLEAN',
 'Approved graph or runtime evidence verifies inadequate authentication for an MCP target.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600)
ON CONFLICT (fact_key,version) DO NOTHING;
