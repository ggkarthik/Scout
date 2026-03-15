alter table servicenow_cmdb_configs
    add column if not exists install_fields varchar(4000),
    add column if not exists discovery_fields varchar(4000);
