-- migration-guard: platform-only
INSERT INTO platform.ai_grid_capability_definitions
    (capability_id, provider, connector, resource_family, optional, lifecycle, remediation)
VALUES
    ('BEDROCK_AGENT_VERSIONS_ALIASES', 'AWS', 'AWS_DISCOVERY', 'BEDROCK_AGENT_VERSIONS', false, 'ACTIVE',
     'Grant bedrock:ListAgentVersions, bedrock:ListAgentAliases, bedrock:GetAgentVersion, bedrock:ListAgentActionGroups, and bedrock:GetAgentActionGroup, then run discovery to verify deployed routing.'),
    ('AWS_TRUSTED_ACTIVITY_EVIDENCE', 'AWS', 'AWS_DISCOVERY', 'AWS_ACTIVITY_EVIDENCE', true, 'ACTIVE',
     'Configure a governed AWS activity evidence source before making runtime claims.')
ON CONFLICT (capability_id) DO UPDATE SET
    provider = excluded.provider,
    connector = excluded.connector,
    resource_family = excluded.resource_family,
    optional = excluded.optional,
    lifecycle = excluded.lifecycle,
    remediation = excluded.remediation;
