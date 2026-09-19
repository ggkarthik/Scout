-- migration-guard: platform-only
INSERT INTO platform.ai_grid_capability_definitions
    (capability_id, provider, connector, resource_family, optional, lifecycle, remediation)
VALUES
    ('AGENTCORE_RUNTIME_TOOLS', 'AWS', 'AWS_DISCOVERY', 'AWS_AGENTCORE_RUNTIME', true, 'ACTIVE',
     'Grant read-only AgentCore runtime, browser, code interpreter, and memory permissions and run discovery.')
ON CONFLICT (capability_id) DO UPDATE SET
    provider = excluded.provider,
    connector = excluded.connector,
    resource_family = excluded.resource_family,
    optional = excluded.optional,
    lifecycle = excluded.lifecycle,
    remediation = excluded.remediation;
