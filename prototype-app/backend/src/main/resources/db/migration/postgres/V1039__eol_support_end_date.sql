-- V1039: Denormalize end-of-active-support date from eol_release onto component tables
-- so EOL + EOS can be surfaced at the component level without joins at query time.

ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS eol_support_end_date DATE;

ALTER TABLE software_instances
    ADD COLUMN IF NOT EXISTS eol_support_end_date DATE;
