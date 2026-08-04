-- migration-guard: platform-only
CREATE TABLE platform.ai_grid_correlation_versions (
    correlation_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    name varchar(512) NOT NULL,
    description text NOT NULL,
    lifecycle varchar(32) NOT NULL CHECK (lifecycle IN ('DRAFT','APPROVED','PUBLISHED','RETIRED')),
    severity varchar(32) NOT NULL,
    precision_threshold double precision NOT NULL CHECK (precision_threshold BETWEEN 0 AND 1),
    max_path_depth integer NOT NULL CHECK (max_path_depth BETWEEN 1 AND 6),
    max_fan_out integer NOT NULL CHECK (max_fan_out BETWEEN 1 AND 100),
    allowed_node_types_json jsonb NOT NULL,
    allowed_edge_types_json jsonb NOT NULL,
    requirements_json jsonb NOT NULL,
    approved_by varchar(255),
    approved_at timestamptz,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (correlation_id, version)
);

CREATE TABLE platform.ai_grid_correlation_precision_reviews (
    id uuid PRIMARY KEY,
    correlation_id varchar(128) NOT NULL,
    correlation_version varchar(32) NOT NULL,
    material_digest varchar(128) NOT NULL,
    sample_size integer NOT NULL CHECK (sample_size > 0),
    accepted_samples integer NOT NULL CHECK (accepted_samples >= 0),
    precision_value double precision NOT NULL CHECK (precision_value BETWEEN 0 AND 1),
    precision_threshold double precision NOT NULL CHECK (precision_threshold BETWEEN 0 AND 1),
    status varchar(32) NOT NULL CHECK (status IN ('PASSED','FAILED','STALE')),
    evidence_reference varchar(1024) NOT NULL,
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (correlation_id, correlation_version)
        REFERENCES platform.ai_grid_correlation_versions(correlation_id, version),
    UNIQUE (correlation_id, correlation_version, material_digest)
);

INSERT INTO platform.ai_grid_correlation_versions
    (correlation_id, version, name, description, lifecycle, severity, precision_threshold,
     max_path_depth, max_fan_out, allowed_node_types_json, allowed_edge_types_json,
     requirements_json, approved_by, approved_at, published_at)
VALUES
('R2_EXTERNAL_SENSITIVE_ACCESS','1.0.0','Externally reachable AI path to sensitive data',
 'Verified external reachability, inadequate authentication, and confirmed sensitive-data access.',
 'PUBLISHED','CRITICAL',0.95,6,100,
 '["AI_AGENT","AI_MODEL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_MODEL","USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","READS_FROM_S3","USES_SEARCH_INDEX","DEPLOYS_MODEL","HAS_DEPLOYMENT","INVOKES_LAMBDA"]',
 '{"validated":["network.internet_reachability_verified","identity.inadequate_authentication_verified","data.sensitive_access_confirmed"],"hypothesis":["network.public_access_configured","identity.local_auth_enabled_configured","data.source_linked"]}',
 'ai-grid-bootstrap',now(),now()),
('R2_EXCESSIVE_TOOL_PRIVILEGE','1.0.0','Tool-enabled agent with excessive privilege',
 'Tool-enabled agent with derived excessive effective privilege and secret or consequential-action access.',
 'PUBLISHED','HIGH',0.93,6,100,
 '["AI_AGENT","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","INVOKES_LAMBDA","ASSUMES_ROLE","HAS_ROLE_ASSIGNMENT","USES_KEY_VAULT_KEY"]',
 '{"validated":["identity.effective_excessive_privilege_derived","impact.secret_or_consequential_access_confirmed"],"hypothesis":["identity.wildcard_permission_observed"]}',
 'ai-grid-bootstrap',now(),now()),
('R2_UNTRUSTED_AUTONOMOUS_EXECUTION','1.0.0','Untrusted input to inadequately controlled autonomous execution',
 'Untrusted input or retrieval reaches autonomous execution without adequate guardrail, isolation, or approval.',
 'PUBLISHED','HIGH',0.92,6,100,
 '["AI_AGENT","AI_GUARDRAIL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","INVOKES_LAMBDA","USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","USES_SEARCH_INDEX","USES_GUARDRAIL"]',
 '{"validated":["input.untrusted_path_verified","agent.autonomous_execution_verified","control.execution_boundary_inadequate_verified"],"hypothesis":["data.source_linked","agent.code_interpreter_enabled_configured","bedrock.agent.guardrail_attached_configured"]}',
 'ai-grid-bootstrap',now(),now())
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,
     allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('identity.inadequate_authentication_verified','1.0.0','BOOLEAN',
 'An approved identity analysis verified inadequate authentication on the exposure entry path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('data.sensitive_access_confirmed','1.0.0','BOOLEAN',
 'Approved data-security evidence confirms that the path can access sensitive data.',
 '["DSPM","GRAPH_ANALYSIS","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('identity.effective_excessive_privilege_derived','1.0.0','BOOLEAN',
 'A versioned identity graph derived excessive effective privilege.',
 '["GRAPH_ANALYSIS"]','["VALIDATED_EXPOSURE"]',3600),
('impact.secret_or_consequential_access_confirmed','1.0.0','BOOLEAN',
 'Approved evidence confirms secret access or a consequential action.',
 '["CIEM","GRAPH_ANALYSIS","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('input.untrusted_path_verified','1.0.0','BOOLEAN',
 'An approved method verified an untrusted input or retrieval path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('agent.autonomous_execution_verified','1.0.0','BOOLEAN',
 'Approved evidence verifies autonomous execution on the path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('control.execution_boundary_inadequate_verified','1.0.0','BOOLEAN',
 'Approved evidence verifies inadequate guardrail, isolation, or approval controls.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600)
ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 56;
UPDATE platform.tenant_schema_versions
SET target_version = 56,
    status = CASE WHEN current_version < 56 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 56;
