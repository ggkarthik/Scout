-- V1068: Remove AWS tag filtering and tag-to-field mapping from the connector.

ALTER TABLE aws_discovery_configs
    DROP COLUMN IF EXISTS tag_filters_json,
    DROP COLUMN IF EXISTS tag_field_mapping_json;

ALTER TABLE aws_discovery_targets
    DROP COLUMN IF EXISTS tag_filters_json;
