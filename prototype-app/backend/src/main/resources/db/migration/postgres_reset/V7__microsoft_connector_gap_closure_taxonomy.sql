INSERT INTO platform.ai_grid_relationship_definitions
    (relationship_type, source, directional, lifecycle, description)
VALUES
    ('VERSION_OF', 'OBSERVATION_V1', true, 'ACTIVE', 'Version belongs to an AI agent.'),
    ('ACTIVE_VERSION', 'OBSERVATION_V1', true, 'ACTIVE', 'Agent designates the active version.'),
    ('USES_PROMPT', 'OBSERVATION_V1', true, 'ACTIVE', 'Active agent version uses a prompt definition.'),
    ('HAS_COMPONENT', 'OBSERVATION_V1', true, 'ACTIVE', 'Agent version contains a component.'),
    ('EXECUTED_AS', 'OBSERVATION_V1', true, 'ACTIVE', 'Execution is associated with an agent artifact.'),
    ('PARTICIPATED_IN', 'OBSERVATION_V1', true, 'ACTIVE', 'Artifact participated in an execution.')
ON CONFLICT (relationship_type) DO NOTHING;
