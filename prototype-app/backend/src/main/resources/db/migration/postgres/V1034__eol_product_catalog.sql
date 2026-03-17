-- EOL product catalog: stores product lifecycle metadata from endoflife.date
create table eol_product_catalog (
    id              bigserial primary key,
    slug            varchar(200) not null,
    cpe_vendor      varchar(200),
    cpe_product     varchar(200),
    purl_type       varchar(100),
    purl_namespace  varchar(200),
    display_name    varchar(200),
    last_fetched_at timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    constraint uk_eol_product_catalog_slug unique (slug)
);

create index idx_eol_catalog_cpe on eol_product_catalog (cpe_vendor, cpe_product)
    where cpe_vendor is not null and cpe_product is not null;

create index idx_eol_catalog_purl on eol_product_catalog (purl_type, purl_namespace)
    where purl_type is not null;

-- EOL release cycles per product
create table eol_release (
    id                    bigserial primary key,
    product_slug          varchar(200) not null references eol_product_catalog(slug) on delete cascade,
    cycle                 varchar(100) not null,
    release_date          date,
    eol_date              date,
    eol_boolean           boolean,
    support_end_date      date,
    extended_support_date date,
    latest_version        varchar(100),
    latest_release_date   date,
    is_lts                boolean not null default false,
    is_eol                boolean not null default false,
    is_eoas               boolean default false,
    is_eoes               boolean default false,
    discontinued          boolean not null default false,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now(),
    constraint uk_eol_release_slug_cycle unique (product_slug, cycle)
);

create index idx_eol_release_product_slug on eol_release (product_slug);
create index idx_eol_release_is_eol on eol_release (is_eol) where is_eol = true;
