-- migration-guard: platform-only
CREATE TABLE IF NOT EXISTS platform.ai_security_policy_distribution (
    policy_id varchar(128) PRIMARY KEY,
    available boolean NOT NULL DEFAULT true,
    default_enabled boolean NOT NULL DEFAULT true,
    updated_by varchar(255) NOT NULL DEFAULT 'system',
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled)
VALUES
    ('AWS_BEDROCK_PUBLIC_KB_S3', true, true),
    ('AWS_BEDROCK_UNAUTH_LAMBDA_URL', true, true),
    ('AWS_BEDROCK_WILDCARD_AGENT_ROLE', true, true),
    ('AWS_BEDROCK_WEAK_GUARDRAIL', true, true),
    ('AWS_BEDROCK_INVOCATION_LOGGING_DISABLED', true, true)
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 45;

UPDATE platform.tenant_schema_versions
SET target_version = 45,
    status = CASE WHEN current_version < 45 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 45;
