-- Denormalized EOL status on software_instances and inventory_components for fast queries
alter table software_instances
    add column if not exists eol_slug           varchar(200),
    add column if not exists eol_cycle          varchar(100),
    add column if not exists eol_date           date,
    add column if not exists is_eol             boolean,
    add column if not exists eol_days_remaining integer,
    add column if not exists eol_checked_at     timestamptz;

alter table inventory_components
    add column if not exists eol_slug           varchar(200),
    add column if not exists eol_cycle          varchar(100),
    add column if not exists eol_date           date,
    add column if not exists is_eol             boolean,
    add column if not exists eol_days_remaining integer,
    add column if not exists eol_checked_at     timestamptz;

create index idx_software_instances_is_eol on software_instances (is_eol)
    where is_eol is not null;
create index idx_inventory_components_is_eol on inventory_components (is_eol)
    where is_eol is not null;
