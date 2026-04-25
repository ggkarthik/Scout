-- V1067: Multi-account AWS discovery targets and EC2 SSM readiness fields.

CREATE TABLE IF NOT EXISTS aws_discovery_targets (
    id                      UUID PRIMARY KEY,
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    config_id               UUID NOT NULL REFERENCES aws_discovery_configs(id) ON DELETE CASCADE,
    account_id              VARCHAR(32),
    account_name            VARCHAR(255),
    role_arn                VARCHAR(2048),
    external_id             VARCHAR(255),
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    regions_json            TEXT NOT NULL DEFAULT '["us-east-1"]',
    resource_types_json     TEXT NOT NULL DEFAULT '["EC2","RDS","LAMBDA","S3","ELB","ECS","EKS"]',
    tag_filters_json        TEXT,
    last_test_status        VARCHAR(64),
    last_test_message       VARCHAR(2000),
    last_tested_at          TIMESTAMP WITH TIME ZONE,
    last_sync_at            TIMESTAMP WITH TIME ZONE,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_targets_config
    ON aws_discovery_targets (config_id);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_targets_tenant_enabled
    ON aws_discovery_targets (tenant_id, enabled);

CREATE UNIQUE INDEX IF NOT EXISTS uk_aws_discovery_targets_config_account
    ON aws_discovery_targets (config_id, account_id)
    WHERE account_id IS NOT NULL;

INSERT INTO aws_discovery_targets (
    id,
    tenant_id,
    config_id,
    account_id,
    account_name,
    role_arn,
    external_id,
    enabled,
    regions_json,
    resource_types_json,
    tag_filters_json,
    last_test_status,
    last_test_message,
    last_tested_at,
    last_sync_at,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    tenant_id,
    id,
    aws_account_id,
    CASE WHEN aws_account_id IS NULL OR aws_account_id = '' THEN 'AWS Account' ELSE 'AWS Account ' || aws_account_id END,
    cross_account_role_arn,
    external_id,
    enabled,
    regions_json,
    resource_types_json,
    tag_filters_json,
    last_test_status,
    last_test_message,
    last_tested_at,
    last_sync_at,
    created_at,
    updated_at
FROM aws_discovery_configs c
WHERE (NULLIF(c.aws_account_id, '') IS NOT NULL OR NULLIF(c.cross_account_role_arn, '') IS NOT NULL)
  AND NOT EXISTS (
      SELECT 1
      FROM aws_discovery_targets t
      WHERE t.config_id = c.id
        AND (
            (c.aws_account_id IS NOT NULL AND t.account_id = c.aws_account_id)
            OR (c.aws_account_id IS NULL AND t.role_arn = c.cross_account_role_arn)
        )
  );

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS ssm_managed BOOLEAN,
    ADD COLUMN IF NOT EXISTS ssm_ping_status VARCHAR(64),
    ADD COLUMN IF NOT EXISTS ssm_last_ping_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS ssm_inventory_available BOOLEAN,
    ADD COLUMN IF NOT EXISTS ssm_inventory_last_captured_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS missing_iam_instance_profile BOOLEAN;

CREATE INDEX IF NOT EXISTS idx_assets_cloud_account_ssm
    ON assets (tenant_id, cloud_provider, cloud_account_id, ssm_managed);
