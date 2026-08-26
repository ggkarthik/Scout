-- migration-guard: platform-only
-- Records approved Phase 1 replacements and retirements without changing historic tenant evidence.
CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_migration_ledger (
    legacy_detector_id varchar(128) PRIMARY KEY,
    legacy_detector_kind varchar(32) NOT NULL,
    legacy_version varchar(32) NOT NULL DEFAULT '1.0.0',
    disposition varchar(48) NOT NULL,
    successor_policy_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    closure_reason varchar(128),
    rationale text NOT NULL,
    approved_by varchar(255) NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    CHECK (legacy_detector_kind IN ('POSTURE_POLICY','CORRELATION')),
    CHECK (disposition IN ('ONE_TO_ONE_REPLACEMENT','SPLIT_REPLACEMENT','RETAINED_GOVERNED_ENVELOPE','RETIRED_INSUFFICIENT_EVIDENCE')),
    CHECK ((disposition = 'RETIRED_INSUFFICIENT_EVIDENCE') = (closure_reason IS NOT NULL))
);

INSERT INTO platform.ai_grid_policy_migration_ledger
    (legacy_detector_id, legacy_detector_kind, disposition, successor_policy_ids_json, closure_reason, rationale, approved_by)
VALUES
('AWS_BEDROCK_WEAK_GUARDRAIL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-002"]',NULL,'Equivalent guardrail-strength evidence is preserved by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_PUBLIC_KB_S3','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-017"]',NULL,'Public knowledge-base source posture is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_UNAUTH_LAMBDA_URL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-006"]',NULL,'Lambda URL authentication evidence is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_WILDCARD_AGENT_ROLE','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-005"]',NULL,'Wildcard execution-role evidence is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_INVOCATION_LOGGING_DISABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-009"]',NULL,'Invocation logging posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_RAI_POLICY_NON_BLOCKING_FILTER','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-010"]',NULL,'RAI filter behavior is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-001"]',NULL,'Public network access posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_LOCAL_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-003"]',NULL,'Local authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-005"]',NULL,'Diagnostic logging posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-017"]',NULL,'Foundry code-interpreter posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-022"]',NULL,'ML endpoint local authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-026"]',NULL,'Search local-admin authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-027"]',NULL,'Bot credential posture is represented by the governed adapter.','ai-grid-phase-1'),
('MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-033"]',NULL,'MCP target health posture is represented by the governed adapter.','ai-grid-phase-1'),
('SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-024"]',NULL,'Sensitive public data-source posture is represented by the governed adapter.','ai-grid-phase-1'),
('BEDROCK_GUARDRAIL_NOT_ATTACHED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-001"]',NULL,'Guardrail attachment posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_BOT_MANAGED_IDENTITY_MISSING','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-028"]',NULL,'Bot managed-identity posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_RBAC_BROAD_ASSIGNMENT','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-030"]',NULL,'Azure RBAC posture is represented by the governed adapter.','ai-grid-phase-1'),
('BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING','POSTURE_POLICY','SPLIT_REPLACEMENT','["AGCF-AWS-003","AGCF-AWS-004"]',NULL,'The legacy combined control is separated into operational-state and role-presence adapters.','ai-grid-phase-1'),
('MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH','POSTURE_POLICY','RETIRED_INSUFFICIENT_EVIDENCE','[]','POLICY_RETIRED_INSUFFICIENT_EVIDENCE','Authoritative public reachability evidence is not available in Phase 1.','ai-grid-phase-1'),
('AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH','POSTURE_POLICY','RETIRED_INSUFFICIENT_EVIDENCE','[]','POLICY_RETIRED_INSUFFICIENT_EVIDENCE','A secret-safe Search data-source authentication classifier is not available in Phase 1.','ai-grid-phase-1'),
('R2_EXTERNAL_SENSITIVE_ACCESS','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-001"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1'),
('R2_EXCESSIVE_TOOL_PRIVILEGE','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-003"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1'),
('R2_UNTRUSTED_AUTONOMOUS_EXECUTION','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-002"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1')
ON CONFLICT (legacy_detector_id) DO NOTHING;
