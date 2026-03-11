-- BLG-011: OCI/container digest support.
--
-- Adds container-artifact-specific columns to the assets table so that
-- CONTAINER_IMAGE assets can carry a content-addressable digest, an optional
-- mutable tag, the originating registry/repository path, and a reference to the
-- base-image manifest digest for layered-analysis workflows.
--
-- All columns are nullable so existing APPLICATION and HOST rows are unaffected.

ALTER TABLE IF EXISTS assets
    ADD COLUMN IF NOT EXISTS image_digest        VARCHAR(255),
    ADD COLUMN IF NOT EXISTS image_tag           VARCHAR(255),
    ADD COLUMN IF NOT EXISTS image_repository    VARCHAR(500),
    ADD COLUMN IF NOT EXISTS base_image_digest   VARCHAR(255);

-- Partial index: only CONTAINER_IMAGE assets have image_digest set.
CREATE INDEX IF NOT EXISTS idx_assets_image_digest
    ON assets (image_digest)
    WHERE image_digest IS NOT NULL;
