-- migration-guard: platform-only
-- Conservative preview controls: every predicate requires direct provider configuration facts.
INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('mcp.endpoint_exposure','1.0.0','STRING','Provider configuration reports an MCP endpoint exposure classification.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.configured_auth_type','1.0.0','STRING','Provider configuration reports MCP authentication classification without credentials or headers.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.target_status','1.0.0','STRING','Provider control plane reports the managed MCP target status.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.sensitivity_confirmed','1.0.0','BOOLEAN','Macie or Purview confirmed sensitive content for the data store.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.public_content_access_configured','1.0.0','BOOLEAN','Provider configuration confirms that data content is publicly accessible.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions
    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,
     artifact_types_json,native_kinds_json,required_resource_families_json,required_facts_json,predicate_json,
     reason_code,remediation,framework_mappings_json,scope_resolution,approved_by,approved_at,published_at)
VALUES
('MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH','1.0.0','Public MCP endpoint without configured authentication',
 'A provider explicitly confirms public network reachability and reports no configured authentication; an external URL alone yields no decision.',
 'CRITICAL','PUBLISHED','POSTURE_FINDING','PREVIEW','["MCP_SERVER"]','[]','[]',
 '[{"factKey":"mcp.endpoint_exposure","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"mcp.configured_auth_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"all":[{"fact":"mcp.endpoint_exposure","eq":"PUBLIC_NETWORK_REACHABLE"},{"fact":"mcp.configured_auth_type","eq":"NONE"}]}',
 'MCP_PUBLIC_ENDPOINT_NO_AUTH','Configure an approved authentication mechanism before exposing the MCP endpoint.',
 '{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now()),
('MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL','1.0.0','MCP target unhealthy or synchronization unsuccessful',
 'A provider-managed MCP target reports a failed terminal or unsuccessful synchronization state.',
 'MEDIUM','PUBLISHED','POSTURE_FINDING','PREVIEW','["MCP_TARGET"]','[]','["AWS_AGENTCORE_GATEWAY_TARGETS"]',
 '[{"factKey":"mcp.target_status","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"fact":"mcp.target_status","in":["FAILED","UPDATE_UNSUCCESSFUL","SYNCHRONIZE_UNSUCCESSFUL"]}',
 'MCP_TARGET_UNHEALTHY','Repair the target configuration and confirm a successful provider synchronization.',
 '{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now()),
('SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS','1.0.0','Sensitive AI data source with public content access',
 'A provider-confirmed sensitive data store is also provider-confirmed to allow public content access.',
 'CRITICAL','PUBLISHED','POSTURE_FINDING','PREVIEW','["DATA_STORE"]','[]','["AWS_MACIE_PII","S3_EXPOSURE"]',
 '[{"factKey":"data.sensitivity_confirmed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"data.public_content_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"all":[{"fact":"data.sensitivity_confirmed","eq":true},{"fact":"data.public_content_access_configured","eq":true}]}',
 'SENSITIVE_DATA_PUBLIC_CONTENT','Restrict content access and verify the data-store policy no longer allows public reads.',
 '{"OWASP_LLM_TOP_10":["LLM02"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now())
ON CONFLICT DO NOTHING;
