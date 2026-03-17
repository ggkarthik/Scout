-- Maps software identities / normalized product keys to endoflife.date product slugs
create table software_eol_mapping (
    id                   bigserial primary key,
    software_identity_id uuid references software_identities(id) on delete set null,
    normalized_key       varchar(500) not null,
    eol_slug             varchar(200) references eol_product_catalog(slug) on delete set null,
    match_confidence     varchar(20),
    match_method         varchar(50),
    confirmed            boolean not null default false,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now(),
    constraint uk_software_eol_mapping_key unique (normalized_key)
);

create index idx_software_eol_mapping_identity on software_eol_mapping (software_identity_id)
    where software_identity_id is not null;
create index idx_software_eol_mapping_slug on software_eol_mapping (eol_slug)
    where eol_slug is not null;
