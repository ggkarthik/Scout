-- migration-guard: tenant-only
--
-- Adds finding_kind to the findings list projection.
--
-- finding_kind exists on the findings table but not on this projection, and neither the
-- projection query path nor the JPA specification path has a predicate for it. The result is
-- that AI policy findings appear in the vulnerability findings list today, and a
-- software-vulnerability view cannot be expressed at all.
--
-- The projection's vulnerability_id column makes this worse rather than better: it is
-- populated with coalesce(vulnerability.external_id, finding.policy_id), so it holds a CVE id
-- for VULNERABILITY rows and an AI policy id for AI rows. package_name and ecosystem are
-- overloaded the same way. Kind therefore has to be its own column -- it cannot be inferred
-- from any of them.
--
-- Backfilled to VULNERABILITY, which matches the findings table default, then made NOT NULL.
-- The projection refresh repopulates every row from the base table, so any AI rows correct
-- themselves on their next refresh rather than staying mislabelled.

ALTER TABLE ${tenantSchema}.finding_list_projection
    ADD COLUMN finding_kind varchar(32);

UPDATE ${tenantSchema}.finding_list_projection p
SET finding_kind = COALESCE(f.finding_kind, 'VULNERABILITY')
FROM ${tenantSchema}.findings f
WHERE f.id = p.finding_id;

UPDATE ${tenantSchema}.finding_list_projection
SET finding_kind = 'VULNERABILITY'
WHERE finding_kind IS NULL;

ALTER TABLE ${tenantSchema}.finding_list_projection
    ALTER COLUMN finding_kind SET NOT NULL;

ALTER TABLE ${tenantSchema}.finding_list_projection
    ALTER COLUMN finding_kind SET DEFAULT 'VULNERABILITY';

-- Selecting one kind is the common case for the split findings views, so it leads the index.
CREATE INDEX idx_finding_list_projection_kind
    ON ${tenantSchema}.finding_list_projection(tenant_id, finding_kind, status);
