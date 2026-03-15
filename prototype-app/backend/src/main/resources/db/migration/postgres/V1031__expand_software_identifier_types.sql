ALTER TABLE software_identifiers
    DROP CONSTRAINT IF EXISTS software_identifiers_id_type_check;

ALTER TABLE software_identifiers
    ADD CONSTRAINT software_identifiers_id_type_check CHECK (
        (id_type)::text = ANY (
            ARRAY[
                'PURL',
                'COORD',
                'CPE',
                'REPO_URL',
                'SWID',
                'MSI_PRODUCT_CODE',
                'SCCM_PACKAGE_ID',
                'INTUNE_PRODUCT_CODE',
                'PRODUCT_HASH',
                'VERSION_HASH',
                'VENDOR_PRODUCT_ID',
                'MAVEN',
                'NPM',
                'PYPI',
                'GOLANG',
                'RPM',
                'DEB',
                'APK'
            ]::text[]
        )
    );
