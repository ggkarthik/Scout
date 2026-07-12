-- tenant_<schema>.software_identity_metadata is read/written by SoftwareIdentityMetadataService
-- (getMetadata / saveMetadata, incl. an INSERT ... ON CONFLICT (tenant_id, software_identity_id) upsert)
-- but was never created by a migration, causing a BadSqlGrammarException (surfaced to callers as a
-- generic "[INTERNAL_ERROR] Internal server error") on PUT/GET /api/inventory/software-identities/{id}/metadata.
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'assets'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.software_identity_metadata (
                    tenant_id uuid NOT NULL,
                    software_identity_id uuid NOT NULL,
                    owner text,
                    licensed text NOT NULL DEFAULT ''''Unknown'''',
                    license_type text,
                    support_group text,
                    recommendation text,
                    recommendation_updated_at timestamptz,
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, software_identity_id),
                    CONSTRAINT fk_software_identity_metadata_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT fk_software_identity_metadata_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id)
                )',
                target_schema.table_schema
        );
    END LOOP;
END
$$;
