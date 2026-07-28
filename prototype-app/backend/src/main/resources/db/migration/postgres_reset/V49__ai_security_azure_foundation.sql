-- migration-guard: platform-only
INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled)
VALUES
    ('AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS', true, true),
    ('AZURE_AI_LOCAL_AUTH_ENABLED', true, true),
    ('AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED', true, true),
    ('AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED', true, false),
    ('AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED', true, true),
    ('AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED', true, true),
    ('AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH', false, false),
    ('AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY', true, true)
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 46;

UPDATE platform.tenant_schema_versions
SET target_version = 46,
    status = CASE WHEN current_version < 46 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 46;
