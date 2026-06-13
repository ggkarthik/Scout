ALTER TABLE tenant_default.campaign_notify_groups
    ADD COLUMN IF NOT EXISTS group_email varchar(255);
