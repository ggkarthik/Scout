-- Add aliases and last_modified to eol_product_catalog for improved matching and conditional fetch
alter table eol_product_catalog
    add column if not exists aliases       text,
    add column if not exists last_modified varchar(50);

-- Add latest_supported_version writeback to inventory tables
alter table software_instances
    add column if not exists latest_supported_version varchar(200);

alter table inventory_components
    add column if not exists latest_supported_version varchar(200);
