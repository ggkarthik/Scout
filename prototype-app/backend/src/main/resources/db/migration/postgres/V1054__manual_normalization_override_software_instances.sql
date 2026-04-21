-- Extend manual normalization override to cover software_instances (host-side records).
-- inventory_components already got these columns in V1053; mirror the same set here
-- so that host software like XenDesktop (source_object_type = 'SOFTWARE_INSTANCE') can
-- also be manually linked to a software identity.
ALTER TABLE software_instances
    ADD COLUMN IF NOT EXISTS manual_identity_id           uuid REFERENCES software_identities(id),
    ADD COLUMN IF NOT EXISTS manual_identity_reason       varchar(400),
    ADD COLUMN IF NOT EXISTS manual_identity_confirmed_by varchar(255),
    ADD COLUMN IF NOT EXISTS manual_identity_confirmed_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_software_instances_manual_identity
    ON software_instances (manual_identity_id)
    WHERE manual_identity_id IS NOT NULL;
