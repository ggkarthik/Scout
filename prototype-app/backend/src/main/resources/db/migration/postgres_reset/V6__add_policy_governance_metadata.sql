-- migration-guard: platform-only
-- Explicit ownership and tenant-boundary metadata for the governed policy catalog.
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS governance_owner varchar(255),
    ADD COLUMN IF NOT EXISTS governance_status varchar(32) NOT NULL DEFAULT 'DRAFT',
    ADD COLUMN IF NOT EXISTS tenant_configurable boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS governance_notes text;

UPDATE platform.ai_grid_policy_versions
   SET governance_owner = coalesce(governance_owner, authored_by, approved_by, 'platform-governance'),
       governance_status = CASE
           WHEN lifecycle IN ('PUBLISHED', 'CANARY') THEN 'PUBLISHED'
           WHEN lifecycle IN ('APPROVED', 'VALIDATED') THEN 'APPROVED'
           WHEN lifecycle IN ('RETIRED', 'DEPRECATED') THEN 'RETIRED'
           ELSE 'DRAFT'
       END
 WHERE governance_owner IS NULL OR governance_status = 'DRAFT';

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_governance_status_check
    CHECK (governance_status IN ('DRAFT', 'APPROVED', 'PUBLISHED', 'RETIRED'));

COMMENT ON COLUMN platform.ai_grid_policy_versions.governance_owner IS 'Platform owner of the policy contract; tenant users cannot change this value.';
COMMENT ON COLUMN platform.ai_grid_policy_versions.tenant_configurable IS 'Whether tenant administrators may configure scope, exceptions, and parameters.';
