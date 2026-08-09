-- migration-guard: platform-only
ALTER TABLE platform.ai_grid_policy_versions ADD COLUMN IF NOT EXISTS parameter_definitions_json jsonb NOT NULL DEFAULT '[]'::jsonb;
UPDATE platform.ai_grid_policy_versions
   SET parameter_definitions_json='[{"key":"minimumGuardrailStrength","type":"ENUM","options":["NONE","LOW","MEDIUM","HIGH"],"defaultValue":"MEDIUM"}]'::jsonb,
       predicate_json='{"all":[{"fact":"bedrock.agent.guardrail_attached_configured","eq":true},{"fact":"bedrock.guardrail.minimum_strength_configured","strength_lt":{"parameter":"minimumGuardrailStrength"}}]}'::jsonb
 WHERE policy_id='AWS_BEDROCK_WEAK_GUARDRAIL' AND version='2.0.0';
