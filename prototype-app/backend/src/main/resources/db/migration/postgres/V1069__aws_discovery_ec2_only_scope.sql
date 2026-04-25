-- V1069: Scope AWS discovery to EC2 compute instances only.

UPDATE aws_discovery_configs
SET resource_types_json = '["EC2"]';

UPDATE aws_discovery_targets
SET resource_types_json = '["EC2"]';

ALTER TABLE aws_discovery_configs
    ALTER COLUMN resource_types_json SET DEFAULT '["EC2"]';

ALTER TABLE aws_discovery_targets
    ALTER COLUMN resource_types_json SET DEFAULT '["EC2"]';
