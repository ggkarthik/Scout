-- migration-guard: platform-only
-- Restore the runtime guardrail policy that is still used by the assessment and policy-configuration paths.
-- V2 removed it as legacy before those consumers were migrated to its governed successor.

INSERT INTO platform.ai_grid_policy_versions
    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,artifact_types_json,
     required_capabilities_json,required_relationships_json,required_resource_families_json,required_facts_json,predicate_json,
     reason_code,remediation,framework_mappings_json,native_kinds_json,scope_resolution,package_digest,authored_by,
     parameter_definitions_json)
VALUES
    ('AWS_BEDROCK_WEAK_GUARDRAIL','2.0.0','Weak attached guardrail content filters',
     'An attached Bedrock guardrail is configured below the approved minimum strength.',
     'HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','["AI_AGENT"]'::jsonb,
     '[]'::jsonb,'["USES_GUARDRAIL"]'::jsonb,'["BEDROCK_AGENTS","BEDROCK_GUARDRAILS"]'::jsonb,
     '[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","maxAgeSeconds":86400,"evidenceClasses":["CONFIGURATION"]},{"factKey":"bedrock.guardrail.minimum_strength_configured","valueType":"STRING","maxAgeSeconds":86400,"evidenceClasses":["CONFIGURATION"]}]'::jsonb,
     '{"all":[{"eq":true,"fact":"bedrock.agent.guardrail_attached_configured"},{"fact":"bedrock.guardrail.minimum_strength_configured","strength_lt":{"parameter":"minimumGuardrailStrength"}}]}'::jsonb,
     'BEDROCK_GUARDRAIL_BELOW_APPROVED_STRENGTH',
     'Configure at least MEDIUM input and output strength for required harmful-content categories.',
     '{"OWASP_LLM_TOP_10":["LLM01"]}'::jsonb,'["AWS_BEDROCK_AGENT"]'::jsonb,'STATIC',
     '2f9d460804cfdf4008e261f1115e3db1','ai-grid-bootstrap',
     '[{"key":"minimumGuardrailStrength","type":"ENUM","options":["NONE","LOW","MEDIUM","HIGH"],"defaultValue":"MEDIUM"}]'::jsonb)
ON CONFLICT (policy_id,version) DO NOTHING;

INSERT INTO platform.ai_grid_policy_release_decisions
    (id,policy_id,policy_version,decision,reason,decided_by,package_digest,approved_package_digest)
VALUES
    (md5('AI_GRID_RUNTIME_COMPAT:AWS_BEDROCK_WEAK_GUARDRAIL:2.0.0:2f9d460804cfdf4008e261f1115e3db1')::uuid,
     'AWS_BEDROCK_WEAK_GUARDRAIL','2.0.0','APPROVED','Runtime compatibility restoration','ai-grid-runtime-compat',
     '2f9d460804cfdf4008e261f1115e3db1','2f9d460804cfdf4008e261f1115e3db1')
ON CONFLICT (id) DO NOTHING;

UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'PUBLISHED', published_at = coalesce(published_at, now())
 WHERE policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' AND version = '2.0.0' AND lifecycle = 'VALIDATED';

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id,available,default_selection,rollout_stage,canary_tenant_ids_json,pinned_version,updated_by,
     approved_package_digest,release_decision_id)
VALUES
    ('AWS_BEDROCK_WEAK_GUARDRAIL',true,'REQUIRED','GENERAL_AVAILABILITY','[]'::jsonb,'2.0.0','ai-grid-runtime-compat',
     '2f9d460804cfdf4008e261f1115e3db1',
     md5('AI_GRID_RUNTIME_COMPAT:AWS_BEDROCK_WEAK_GUARDRAIL:2.0.0:2f9d460804cfdf4008e261f1115e3db1')::uuid)
ON CONFLICT (policy_id) DO NOTHING;
