-- migration-guard: platform-only
CREATE TABLE platform.ai_grid_technology_versions (
    technology_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    display_name varchar(255) NOT NULL,
    provider varchar(32) NOT NULL,
    lifecycle varchar(32) NOT NULL,
    aliases_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (technology_id, version)
);

CREATE TABLE platform.ai_grid_fact_definitions (
    fact_key varchar(255) NOT NULL,
    version varchar(32) NOT NULL,
    value_type varchar(32) NOT NULL,
    claim_semantics text NOT NULL,
    allowed_evidence_classes_json jsonb NOT NULL,
    allowed_workflow_uses_json jsonb NOT NULL,
    default_max_age_seconds bigint,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (fact_key, version)
);

CREATE TABLE platform.ai_grid_policy_versions (
    policy_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    name varchar(512) NOT NULL,
    description text NOT NULL,
    severity varchar(32) NOT NULL,
    lifecycle varchar(32) NOT NULL,
    workflow_class varchar(32) NOT NULL,
    default_selection varchar(32) NOT NULL,
    artifact_types_json jsonb NOT NULL,
    required_capabilities_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_relationships_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_resource_families_json jsonb NOT NULL,
    required_facts_json jsonb NOT NULL,
    predicate_json jsonb NOT NULL,
    reason_code varchar(128) NOT NULL,
    remediation text NOT NULL,
    framework_mappings_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    approved_by varchar(255),
    approved_at timestamptz,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version),
    CHECK (lifecycle IN ('DRAFT','VALIDATED','APPROVED','CANARY','PUBLISHED','RETIRED'))
);

INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES
    ('AWS_BEDROCK', '1.0.0', 'Amazon Bedrock', 'AWS', 'ACTIVE',
     '["BEDROCK_AGENTS","BEDROCK_GUARDRAILS","BEDROCK_KNOWLEDGE_BASES","BEDROCK_INVOCATION_LOGGING"]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('bedrock.agent.guardrail_attached_configured', '1.0.0', 'BOOLEAN',
     'Provider configuration states that the agent has an attached guardrail.', '["CONFIGURATION"]', '["POSTURE_FINDING"]', 86400),
    ('bedrock.guardrail.minimum_strength_configured', '1.0.0', 'STRING',
     'Minimum configured input/output strength across the attached guardrail content filters.', '["CONFIGURATION"]', '["POSTURE_FINDING"]', 86400),
    ('network.public_access_configured', '1.0.0', 'BOOLEAN',
     'Provider configuration permits public network access.', '["CONFIGURATION"]', '["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]', 86400),
    ('network.internet_reachability_verified', '1.0.0', 'BOOLEAN',
     'An approved reachability method verified an Internet path.', '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]', '["VALIDATED_EXPOSURE"]', 3600)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions (
    policy_id, version, name, description, severity, lifecycle, workflow_class,
    default_selection, artifact_types_json, required_relationships_json,
    required_resource_families_json, required_facts_json, predicate_json,
    reason_code, remediation, framework_mappings_json, approved_by, approved_at, published_at
) VALUES (
    'AWS_BEDROCK_WEAK_GUARDRAIL', '2.0.0', 'Weak attached guardrail content filters',
    'An attached Bedrock guardrail is configured below the approved minimum strength.',
    'HIGH', 'PUBLISHED', 'POSTURE_FINDING', 'REQUIRED', '["AI_AGENT"]', '["USES_GUARDRAIL"]',
    '["BEDROCK_AGENTS","BEDROCK_GUARDRAILS"]',
    '[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"bedrock.guardrail.minimum_strength_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
    '{"all":[{"fact":"bedrock.agent.guardrail_attached_configured","eq":true},{"fact":"bedrock.guardrail.minimum_strength_configured","in":["NONE","LOW"]}]}',
    'BEDROCK_GUARDRAIL_BELOW_APPROVED_STRENGTH',
    'Configure at least MEDIUM input and output strength for required harmful-content categories.',
    '{"OWASP_LLM_TOP_10":["LLM01"]}', 'ai-grid-bootstrap', now(), now()
) ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 48;
UPDATE platform.tenant_schema_versions
SET target_version = 48,
    status = CASE WHEN current_version < 48 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 48;
