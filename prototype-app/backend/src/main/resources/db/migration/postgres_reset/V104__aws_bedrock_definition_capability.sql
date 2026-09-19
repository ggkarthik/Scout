-- migration-guard: platform-only
INSERT INTO platform.ai_grid_capability_definitions
    (capability_id, provider, connector, resource_family, optional, lifecycle, remediation)
VALUES
    ('BEDROCK_PROMPTS_TOOLS', 'AWS', 'AWS_DISCOVERY', 'BEDROCK_PROMPTS', true, 'ACTIVE',
     'Grant read-only Bedrock prompt, flow, and action-group permissions and run discovery to verify the definition graph.')
ON CONFLICT (capability_id) DO UPDATE SET
    provider = excluded.provider,
    connector = excluded.connector,
    resource_family = excluded.resource_family,
    optional = excluded.optional,
    lifecycle = excluded.lifecycle,
    remediation = excluded.remediation;
