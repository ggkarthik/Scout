-- Widen servicenow_cmdb_configs columns that were too narrow (varchar 255)
-- to match the entity declarations (install_fields/discovery_fields/queries → 4000,
-- last_test_message → 2000).
ALTER TABLE tenant_default.servicenow_cmdb_configs
    ALTER COLUMN install_fields     TYPE varchar(4000),
    ALTER COLUMN install_query      TYPE varchar(4000),
    ALTER COLUMN discovery_fields   TYPE varchar(4000),
    ALTER COLUMN discovery_query    TYPE varchar(4000),
    ALTER COLUMN last_test_message  TYPE varchar(2000);
