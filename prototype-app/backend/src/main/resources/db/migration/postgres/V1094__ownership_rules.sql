create table ownership_rules (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id),
    name text not null,
    condition_json text not null default '{"logic":"AND","conditions":[]}',
    user_group text not null,
    execution_order int not null default 0,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index idx_ownership_rules_tenant_order on ownership_rules(tenant_id, execution_order);

alter table findings add column owner_group text;
