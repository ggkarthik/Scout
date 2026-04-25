-- V1063: AWS Cloud Discovery connector configuration table
-- Stores authentication, scope, tag-filter, and schedule settings per tenant.
-- credential_secret is NEVER returned in API responses and NEVER logged.

CREATE TABLE IF NOT EXISTS aws_discovery_configs (
    id                      UUID         PRIMARY KEY,
    tenant_id               UUID         NOT NULL REFERENCES tenants(id),
    source_system           VARCHAR(80)  NOT NULL DEFAULT 'aws',

    -- Authentication
    auth_type               VARCHAR(32)  NOT NULL DEFAULT 'INSTANCE_METADATA',
    access_key_id           VARCHAR(255),
    credential_secret       VARCHAR(4000),       -- secret access key; never logged, never returned in API
    cross_account_role_arn  VARCHAR(2048),
    external_id             VARCHAR(255),
    aws_account_id          VARCHAR(32),         -- resolved via STS GetCallerIdentity; displayed read-only

    -- Scope
    regions_json            TEXT         NOT NULL DEFAULT '["us-east-1"]',
    -- JSON array of resource type strings: ["EC2","RDS","LAMBDA","S3","ELB","ECS","EKS"]
    resource_types_json     TEXT         NOT NULL DEFAULT '["EC2","RDS","LAMBDA","S3","ELB","ECS","EKS"]',
    -- JSON array of tag filter objects: [{key, value, mode}] where mode = INCLUDE | EXCLUDE
    tag_filters_json        TEXT,
    -- JSON object mapping field names to AWS tag keys:
    -- {"environment": "Environment", "ownerTeam": "Owner", "criticality": "Criticality"}
    tag_field_mapping_json  TEXT,
    -- Schedule
    enabled                 BOOLEAN      NOT NULL DEFAULT TRUE,
    auto_sync_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    interval_minutes        INTEGER      NOT NULL DEFAULT 1440,

    -- Connection test status
    last_test_status        VARCHAR(64),
    last_test_message       VARCHAR(2000),
    last_tested_at          TIMESTAMP WITH TIME ZONE,

    -- Sync status
    last_sync_at            TIMESTAMP WITH TIME ZONE,

    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_aws_discovery_configs_tenant_source
    ON aws_discovery_configs (tenant_id, source_system);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_configs_enabled
    ON aws_discovery_configs (enabled, auto_sync_enabled);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_configs_tenant
    ON aws_discovery_configs (tenant_id);
