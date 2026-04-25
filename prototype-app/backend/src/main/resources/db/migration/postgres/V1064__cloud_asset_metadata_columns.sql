-- V1064: Cloud-specific metadata columns on the assets table.
-- AssetType.CLOUD_RESOURCE is a new enum value (Java-only change; column is VARCHAR).
-- These columns are NULL for non-cloud assets.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS cloud_provider            VARCHAR(32),
    ADD COLUMN IF NOT EXISTS cloud_region              VARCHAR(64),
    ADD COLUMN IF NOT EXISTS cloud_availability_zone   VARCHAR(64),
    ADD COLUMN IF NOT EXISTS cloud_account_id          VARCHAR(64),
    ADD COLUMN IF NOT EXISTS cloud_resource_type       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS cloud_instance_type       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS cloud_vpc_id              VARCHAR(128),
    ADD COLUMN IF NOT EXISTS cloud_subnet_id           VARCHAR(128),
    ADD COLUMN IF NOT EXISTS cloud_arn                 VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS cloud_tags_json           TEXT,
    ADD COLUMN IF NOT EXISTS cloud_launch_time         TIMESTAMP WITH TIME ZONE;

-- Composite index for cloud inventory listing queries filtered by provider + type
CREATE INDEX IF NOT EXISTS idx_assets_cloud_provider_type
    ON assets (cloud_provider, cloud_resource_type)
    WHERE cloud_provider IS NOT NULL;

-- Index for ARN-based lookups (identity deduplication)
CREATE INDEX IF NOT EXISTS idx_assets_cloud_arn
    ON assets (cloud_arn)
    WHERE cloud_arn IS NOT NULL;
