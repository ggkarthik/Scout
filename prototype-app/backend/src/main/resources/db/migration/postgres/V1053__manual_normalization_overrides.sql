-- Manual normalization override: analyst can link a component to the correct software identity
-- even when the automated normalization pipeline cannot resolve it.
ALTER TABLE inventory_components
    ADD COLUMN IF NOT EXISTS manual_identity_id          uuid REFERENCES software_identities(id),
    ADD COLUMN IF NOT EXISTS manual_identity_reason      varchar(400),
    ADD COLUMN IF NOT EXISTS manual_identity_confirmed_by varchar(255),
    ADD COLUMN IF NOT EXISTS manual_identity_confirmed_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_inventory_components_manual_identity
    ON inventory_components (manual_identity_id)
    WHERE manual_identity_id IS NOT NULL;
