create table if not exists sccm_cmdb_configs (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    source_system varchar(80) not null default 'sccm',
    jdbc_url varchar(1000),
    auth_type varchar(32) not null default 'SQL_AUTH',
    username varchar(255),
    credential_secret varchar(4000),
    site_code varchar(20),
    database_name varchar(255) not null default 'CM_P01',
    fetch_size integer not null default 500,
    query_timeout_seconds integer not null default 120,
    mock_mode boolean not null default false,
    enabled boolean not null default true,
    auto_sync_enabled boolean not null default false,
    interval_minutes integer not null default 1440,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamp with time zone,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

create unique index if not exists uk_sccm_cmdb_configs_tenant_source
    on sccm_cmdb_configs (tenant_id, source_system);

create index if not exists idx_sccm_cmdb_configs_enabled
    on sccm_cmdb_configs (enabled, auto_sync_enabled);

create index if not exists idx_sccm_cmdb_configs_tenant
    on sccm_cmdb_configs (tenant_id);
