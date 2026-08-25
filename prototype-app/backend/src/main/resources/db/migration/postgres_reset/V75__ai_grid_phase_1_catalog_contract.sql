-- migration-guard: platform-only
CREATE TABLE platform.ai_grid_control_objectives (
    control_objective_id varchar(128) PRIMARY KEY,
    name varchar(512) NOT NULL,
    security_intent text NOT NULL,
    remediation_intent text NOT NULL,
    owner varchar(255) NOT NULL,
    lifecycle varchar(32) NOT NULL CHECK (lifecycle IN ('DRAFT','ACTIVE','RETIRED')),
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS control_objective_id varchar(128) REFERENCES platform.ai_grid_control_objectives(control_objective_id),
    ADD COLUMN IF NOT EXISTS provider varchar(32),
    ADD COLUMN IF NOT EXISTS evaluation_mode varchar(32),
    ADD COLUMN IF NOT EXISTS evaluation_definition_json jsonb,
    ADD COLUMN IF NOT EXISTS base_evidence_tiers_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS conditional_capabilities_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS certification_parameter_profile_json jsonb;

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_provider_check CHECK (provider IS NULL OR provider IN ('AWS','AZURE','MULTI_CLOUD')),
    ADD CONSTRAINT ai_grid_policy_evaluation_mode_check CHECK (evaluation_mode IS NULL OR evaluation_mode IN ('ARTIFACT_FACTS','DIRECT_RELATIONSHIP','CORRELATION_PATH'));

CREATE TABLE platform.ai_grid_capability_definitions (
    capability_id varchar(128) PRIMARY KEY,
    provider varchar(32) NOT NULL CHECK (provider IN ('AWS','AZURE','MULTI_CLOUD')),
    connector varchar(128) NOT NULL,
    resource_family varchar(128) NOT NULL,
    optional boolean NOT NULL DEFAULT false,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','RETIRED')),
    remediation text NOT NULL
);

INSERT INTO platform.ai_grid_capability_definitions
    (capability_id,provider,connector,resource_family,optional,remediation)
VALUES
    ('BEDROCK_AGENTS','AWS','AWS_DISCOVERY','BEDROCK_AGENTS',false,'Grant the read-only Bedrock Agents permissions and run discovery.'),
    ('BEDROCK_GUARDRAILS','AWS','AWS_DISCOVERY','BEDROCK_GUARDRAILS',false,'Grant the read-only Bedrock Guardrails permissions and run discovery.'),
    ('BEDROCK_KNOWLEDGE_BASES','AWS','AWS_DISCOVERY','BEDROCK_KNOWLEDGE_BASES',false,'Grant the read-only Bedrock Knowledge Bases permissions and run discovery.'),
    ('BEDROCK_MODELS_JOBS','AWS','AWS_DISCOVERY','BEDROCK_MODELS_AND_JOBS',false,'Grant the read-only Bedrock models and jobs permissions and run discovery.'),
    ('BEDROCK_INVOCATION_LOGGING','AWS','AWS_DISCOVERY','BEDROCK_INVOCATION_LOGGING',false,'Grant the read-only Bedrock logging permissions and run discovery.'),
    ('IAM_ROLE_POLICIES','AWS','AWS_DISCOVERY','IAM_ROLE_POLICIES',false,'Grant the read-only IAM role-policy permissions and run discovery.'),
    ('LAMBDA_URLS','AWS','AWS_DISCOVERY','LAMBDA_URLS',false,'Grant the read-only Lambda URL permissions and run discovery.'),
    ('AGENTCORE_GATEWAYS_TARGETS','AWS','AWS_DISCOVERY','AGENTCORE_GATEWAYS_AND_TARGETS',false,'Grant the read-only AgentCore gateway and target permissions and run discovery.'),
    ('SAGEMAKER_DOMAINS_MODELS_ENDPOINTS','AWS','AWS_DISCOVERY','SAGEMAKER_DOMAINS_MODELS_ENDPOINTS',false,'Grant the read-only SageMaker permissions and run discovery.'),
    ('MACIE_CLASSIFICATION','AWS','AWS_MACIE','MACIE_CLASSIFICATION',true,'Enable the read-only Macie classification integration for the applicable account.'),
    ('AI_ACCOUNTS','AZURE','AZURE_DISCOVERY','AI_ACCOUNTS',false,'Grant the read-only Azure AI Account permissions and run discovery.'),
    ('DIAGNOSTIC_SETTINGS','AZURE','AZURE_DISCOVERY','DIAGNOSTIC_SETTINGS',false,'Grant the read-only diagnostic settings permissions and run discovery.'),
    ('FOUNDRY_DEPLOYMENTS_RAI','AZURE','AZURE_DISCOVERY','FOUNDRY_DEPLOYMENTS_AND_RAI',false,'Grant the read-only Foundry deployment and RAI permissions and run discovery.'),
    ('FOUNDRY_AGENTS_TOOLS','AZURE','AZURE_DISCOVERY','FOUNDRY_AGENTS_AND_TOOLS',true,'Enable the read-only Foundry agent and tool metadata collection.'),
    ('ML_WORKSPACES_ENDPOINTS','AZURE','AZURE_DISCOVERY','ML_WORKSPACES_AND_ENDPOINTS',false,'Grant the read-only Azure ML workspace and endpoint permissions and run discovery.'),
    ('SEARCH_CONTROL_PLANE','AZURE','AZURE_DISCOVERY','SEARCH_CONTROL_PLANE',false,'Grant the read-only Azure AI Search control-plane permissions and run discovery.'),
    ('BOT_CONFIGURATION','AZURE','AZURE_DISCOVERY','BOT_CONFIGURATION',false,'Grant the read-only Azure Bot configuration permissions and run discovery.'),
    ('RBAC_ASSIGNMENTS','AZURE','AZURE_DISCOVERY','RBAC_ASSIGNMENTS',false,'Grant the read-only Azure RBAC assignment permissions and run discovery.'),
    ('PURVIEW_CLASSIFICATION','AZURE','AZURE_PURVIEW','PURVIEW_CLASSIFICATION',true,'Enable the read-only Purview classification integration for the applicable subscription.'),
    ('FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE','AZURE','AZURE_DISCOVERY','FOUNDRY_AGENTS_SEARCH_DATA_PLANE',true,'Enable the required read-only Foundry Agents or Search data-plane metadata collection.'),
    ('MULTI_CLOUD_GRAPH','MULTI_CLOUD','AI_GRID_GRAPH','DIRECT_RELATIONSHIPS',false,'Collect complete, fresh direct relationship evidence for the coverage epoch.')
ON CONFLICT (capability_id) DO NOTHING;

UPDATE platform.tenant_schema_versions
   SET target_version = 66,
       status = CASE WHEN current_version < 66 THEN 'PENDING' ELSE status END,
       updated_at = now()
 WHERE target_version < 66;
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 66;
