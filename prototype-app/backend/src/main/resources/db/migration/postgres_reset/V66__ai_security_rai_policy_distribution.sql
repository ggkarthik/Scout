-- migration-guard: platform-only
INSERT INTO platform.ai_security_policy_distribution (
    policy_id,
    available,
    default_enabled,
    updated_by
)
VALUES (
    'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    true,
    true,
    'ai-security-policy-registry'
)
ON CONFLICT (policy_id) DO NOTHING;
