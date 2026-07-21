-- migration-guard: platform-only
ALTER TABLE platform.tenant_memberships
    ADD COLUMN IF NOT EXISTS provenance varchar(32) NOT NULL DEFAULT 'MANUAL';

UPDATE platform.tenant_memberships
SET provenance = 'TENANT_INVITE'
WHERE invited_by IS NOT NULL
  AND provenance = 'MANUAL';

CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_memberships_user_tenant
    ON platform.tenant_memberships (user_id, tenant_id);

ALTER TABLE platform.tenant_support_grants
    ALTER COLUMN expires_at DROP NOT NULL;
