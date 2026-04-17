-- Extended ownership fields synced from ServiceNow CMDB
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS managed_by    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS department    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS support_group VARCHAR(255),
    ADD COLUMN IF NOT EXISTS assigned_to   VARCHAR(255);

ALTER TABLE cis
    ADD COLUMN IF NOT EXISTS managed_by    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS department    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS support_group VARCHAR(255),
    ADD COLUMN IF NOT EXISTS assigned_to   VARCHAR(255);
