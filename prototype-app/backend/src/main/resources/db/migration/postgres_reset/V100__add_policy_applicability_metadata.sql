-- migration-guard: platform-only
-- Platform-owned applicability metadata. Tenants consume this catalog metadata but cannot edit it.
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS evaluation_subject varchar(32) NOT NULL DEFAULT 'ARTIFACT',
    ADD COLUMN IF NOT EXISTS relationship_types_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS applicability_notes text;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ai_grid_policy_evaluation_subject_check' AND conrelid = 'platform.ai_grid_policy_versions'::regclass) THEN
        ALTER TABLE platform.ai_grid_policy_versions ADD CONSTRAINT ai_grid_policy_evaluation_subject_check
            CHECK (evaluation_subject IN ('ARTIFACT', 'RELATIONSHIP', 'SYSTEM', 'RESOURCE_CONFIGURATION'));
    END IF;
END $$;

-- Older bundled packages used empty artifactTypes arrays. Derive canonical bindings from
-- platform-owned native kinds without changing tenant configuration state.
ALTER TABLE platform.ai_grid_policy_versions DISABLE TRIGGER trg_ai_grid_approved_package_immutable;
UPDATE platform.ai_grid_policy_versions
SET native_kinds_json = CASE
    WHEN upper(name) LIKE '%BEDROCK%AGENT%' THEN '["AWS_BEDROCK_AGENT"]'::jsonb
    WHEN upper(name) LIKE '%FOUNDRY%AGENT%' THEN '["AZURE_FOUNDRY_AGENT"]'::jsonb
    WHEN upper(name) LIKE '%BOT%' THEN '["AZURE_BOT_SERVICE"]'::jsonb
    ELSE native_kinds_json
END
WHERE jsonb_typeof(native_kinds_json) = 'array' AND jsonb_array_length(native_kinds_json) = 0;
UPDATE platform.ai_grid_policy_versions
SET artifact_types_json = CASE
    WHEN evaluation_mode = 'CORRELATION_PATH' THEN '["SYSTEM"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%GATEWAY%' THEN '["MCP_GATEWAY"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%TARGET%' THEN '["MCP_TARGET"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%MCP%' THEN '["MCP_SERVER"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%AGENT%' THEN '["AI_AGENT"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%GUARDRAIL%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%RAI%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%FILTER%' THEN '["AI_GUARDRAIL"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%MODEL%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%ENDPOINT%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%SAGEMAKER%' THEN '["AI_MODEL"]'::jsonb
    WHEN upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%SEARCH%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%KNOWLEDGE%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%DATA_SOURCE%'
      OR upper(coalesce(native_kinds_json::text, '') || ' ' || name) LIKE '%DATASTORE%' THEN '["KNOWLEDGE_BASE"]'::jsonb
    ELSE '["OTHER_AI_ARTIFACT"]'::jsonb
END,
evaluation_subject = CASE WHEN evaluation_mode = 'CORRELATION_PATH' THEN 'SYSTEM' ELSE 'ARTIFACT' END,
applicability_notes = CASE WHEN evaluation_mode = 'CORRELATION_PATH'
    THEN 'Evaluates governed relationships across multiple AI artifacts; SYSTEM is the evaluation subject.'
    ELSE 'Canonical artifact applicability derived from the platform package native kinds.' END
WHERE jsonb_typeof(artifact_types_json) = 'array' AND jsonb_array_length(artifact_types_json) = 0;

UPDATE platform.ai_grid_policy_versions
SET evaluation_subject = CASE WHEN evaluation_mode = 'CORRELATION_PATH' THEN 'SYSTEM' ELSE 'ARTIFACT' END
WHERE evaluation_subject IS NULL;
ALTER TABLE platform.ai_grid_policy_versions ENABLE TRIGGER trg_ai_grid_approved_package_immutable;

COMMENT ON COLUMN platform.ai_grid_policy_versions.evaluation_subject IS 'Platform-owned subject boundary: artifact, relationship, system correlation, or resource configuration.';
COMMENT ON COLUMN platform.ai_grid_policy_versions.relationship_types_json IS 'Platform-owned relationship bindings used by relationship and correlation policy evaluation.';
COMMENT ON COLUMN platform.ai_grid_policy_versions.applicability_notes IS 'Human-readable platform explanation of the canonical applicability binding.';
