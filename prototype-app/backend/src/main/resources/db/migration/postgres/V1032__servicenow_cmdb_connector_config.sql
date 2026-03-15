create table if not exists servicenow_cmdb_configs (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    source_system varchar(80) not null,
    base_url varchar(1000),
    auth_type varchar(32) not null default 'BASIC',
    username varchar(255),
    credential_secret varchar(4000),
    install_table varchar(255) not null default 'cmdb_sam_sw_install',
    discovery_model_table varchar(255) not null default 'cmdb_sam_sw_discovery_model',
    ci_table varchar(255) not null default 'cmdb_ci',
    install_query varchar(4000),
    discovery_query varchar(4000),
    page_size integer not null default 1000,
    enabled boolean not null default true,
    auto_sync_enabled boolean not null default false,
    interval_minutes integer not null default 1440,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamp with time zone,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

create unique index if not exists uk_servicenow_cmdb_configs_tenant_source
    on servicenow_cmdb_configs (tenant_id, source_system);

create index if not exists idx_servicenow_cmdb_configs_enabled
    on servicenow_cmdb_configs (enabled, auto_sync_enabled);

create index if not exists idx_servicenow_cmdb_configs_tenant
    on servicenow_cmdb_configs (tenant_id);
