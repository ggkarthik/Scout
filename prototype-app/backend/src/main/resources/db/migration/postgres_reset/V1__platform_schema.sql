-- migration-guard: platform-only
-- Consolidated clean-slate baseline. Generated from the ordered V1–V95 platform catalog.

-- source: V1__platform_and_default_tenant_schemas.sql
CREATE SCHEMA IF NOT EXISTS platform;
CREATE SCHEMA IF NOT EXISTS tenant_default;

CREATE TABLE IF NOT EXISTS platform.tenants (
    id uuid PRIMARY KEY,
    billing_ref varchar(255),
    created_at timestamptz NOT NULL,
    deleted_at timestamptz,
    demo_created_by varchar(255),
    demo_expires_at timestamptz,
    demo_owner_email varchar(255),
    demo_source varchar(255),
    expired_at timestamptz,
    max_connector_count integer NOT NULL,
    max_daily_exposure_refreshes integer NOT NULL,
    max_daily_sbom_uploads integer NOT NULL,
    max_export_rows integer NOT NULL,
    max_service_account_count integer NOT NULL,
    name varchar(255) NOT NULL,
    plan_code varchar(255) NOT NULL,
    purge_error varchar(255),
    purge_started_at timestamptz,
    purge_status varchar(255),
    purged_at timestamptz,
    schema_name varchar(255) NOT NULL,
    slug varchar(255),
    status varchar(255) NOT NULL,
    suspended_at timestamptz,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_tenants_name UNIQUE (name),
    CONSTRAINT uk_tenants_schema_name UNIQUE (schema_name),
    CONSTRAINT uk_tenants_slug UNIQUE (slug)
);

CREATE TABLE IF NOT EXISTS platform.app_users (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    display_name varchar(255),
    email varchar(255),
    external_subject varchar(255) NOT NULL,
    last_seen_at timestamptz,
    password_hash varchar(255),
    password_set_at timestamptz,
    password_setup_token_expires_at timestamptz,
    password_setup_token_hash varchar(255),
    platform_owner boolean NOT NULL,
    status varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_app_users_external_subject UNIQUE (external_subject)
);

CREATE TABLE IF NOT EXISTS platform.tenant_memberships (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    role varchar(255) NOT NULL,
    status varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    invited_by uuid,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    CONSTRAINT fk_tenant_memberships_invited_by FOREIGN KEY (invited_by) REFERENCES platform.app_users (id),
    CONSTRAINT fk_tenant_memberships_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_memberships_user FOREIGN KEY (user_id) REFERENCES platform.app_users (id)
);

CREATE TABLE IF NOT EXISTS platform.app_user_global_roles (
    id uuid PRIMARY KEY,
    app_user_id uuid NOT NULL,
    role varchar(64) NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT fk_app_user_global_roles_user FOREIGN KEY (app_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_app_user_global_roles_user_role UNIQUE (app_user_id, role)
);

CREATE INDEX IF NOT EXISTS idx_app_user_global_roles_role
    ON platform.app_user_global_roles (role);

CREATE TABLE IF NOT EXISTS platform.tenant_support_grants (
    id uuid PRIMARY KEY,
    accepted_at timestamptz,
    access_mode varchar(255) NOT NULL,
    expires_at timestamptz NOT NULL,
    invited_platform_subject varchar(255) NOT NULL,
    reason varchar(255) NOT NULL,
    requested_at timestamptz NOT NULL,
    revoked_at timestamptz,
    scope varchar(255),
    status varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    accepted_by uuid,
    granted_by uuid NOT NULL,
    revoked_by uuid,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_tenant_support_grants_accepted_by FOREIGN KEY (accepted_by) REFERENCES platform.app_users (id),
    CONSTRAINT fk_tenant_support_grants_granted_by FOREIGN KEY (granted_by) REFERENCES platform.app_users (id),
    CONSTRAINT fk_tenant_support_grants_revoked_by FOREIGN KEY (revoked_by) REFERENCES platform.app_users (id),
    CONSTRAINT fk_tenant_support_grants_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_support_grants_subject_status_expires
    ON platform.tenant_support_grants (invited_platform_subject, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_tenant_support_grants_tenant_requested
    ON platform.tenant_support_grants (tenant_id, requested_at);

-- Plan + entitlement platform tables. These were originally created pre-baseline and were missing
-- from the migration set, so a freshly provisioned database (CI / integration tests) failed at
-- V24__enable_investigation_agent_all_plans.sql ("relation platform.plan_entitlements does not
-- exist"). They are created here, in foreign-key dependency order, before V18 (which also creates
-- and seeds plan_definitions) and V24. All use IF NOT EXISTS so existing databases are unaffected.
-- Seed rows are restored idempotently by V27__restore_entitlement_seed_data.sql (after V18 seeds the
-- plan_definitions rows that plan_entitlements references).
CREATE TABLE IF NOT EXISTS platform.plan_definitions (
    code varchar(64) PRIMARY KEY,
    display_name varchar(120) NOT NULL,
    status varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS platform.entitlement_definitions (
    key varchar(128) PRIMARY KEY,
    category varchar(64) NOT NULL,
    value_type varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS platform.plan_entitlements (
    plan_code varchar(64) NOT NULL,
    entitlement_key varchar(128) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_plan_entitlements PRIMARY KEY (plan_code, entitlement_key),
    CONSTRAINT fk_plan_entitlements_plan_code
        FOREIGN KEY (plan_code) REFERENCES platform.plan_definitions (code),
    CONSTRAINT fk_plan_entitlements_entitlement_key
        FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions (key)
);

CREATE TABLE IF NOT EXISTS platform.vulnerabilities (
    id uuid PRIMARY KEY,
    external_id varchar(50) NOT NULL,
    source varchar(20) NOT NULL,
    title varchar(500) NOT NULL,
    description_snippet varchar(500),
    description_archive_key varchar(200),
    cvss_score double precision,
    severity varchar(20) NOT NULL,
    epss_score double precision,
    in_kev boolean NOT NULL,
    cvss_vector varchar(300),
    cvss_version varchar(20),
    attack_vector varchar(20),
    attack_complexity varchar(20),
    privileges_required varchar(20),
    user_interaction varchar(20),
    cvss_scope varchar(20),
    exploitability_score double precision,
    impact_score double precision,
    cwe_ids varchar(200),
    source_identifier varchar(255),
    vuln_status varchar(80),
    kev_date_added date,
    kev_due_date date,
    kev_required_action varchar(500),
    references_json text,
    raw_payload_archive_key varchar(200),
    published_at timestamptz,
    last_modified_at timestamptz,
    epss_updated_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_vulnerabilities_external_id UNIQUE (external_id)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_external_cvss_lastmod_updated
    ON platform.vulnerabilities (external_id, cvss_score, last_modified_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_lastmod_updated
    ON platform.vulnerabilities (cvss_score, last_modified_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
    ON platform.vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_in_kev
    ON platform.vulnerabilities (in_kev);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss
    ON platform.vulnerabilities (epss_score);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published
    ON platform.vulnerabilities (published_at);

CREATE TABLE IF NOT EXISTS platform.software_identities (
    id uuid PRIMARY KEY,
    canonical_key varchar(400) NOT NULL,
    display_name varchar(300) NOT NULL,
    vendor varchar(255),
    product varchar(255),
    product_hash varchar(255),
    purl varchar(1200),
    cpe23 varchar(1200),
    vendor_product_id varchar(255),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_software_identities_canonical_key UNIQUE (canonical_key)
);

CREATE INDEX IF NOT EXISTS idx_software_identity_key
    ON platform.software_identities (canonical_key);

CREATE TABLE IF NOT EXISTS platform.software_identifiers (
    id uuid PRIMARY KEY,
    confidence double precision,
    created_at timestamptz NOT NULL,
    id_type varchar(40) NOT NULL,
    normalized_value varchar(1000) NOT NULL,
    provenance_note varchar(500),
    raw_value varchar(1000),
    source varchar(80) NOT NULL,
    updated_at timestamptz NOT NULL,
    verified boolean NOT NULL,
    software_identity_id uuid NOT NULL,
    CONSTRAINT fk_software_identifiers_software_identity
        FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT uk_software_identifier_identity_type_value
        UNIQUE (software_identity_id, id_type, normalized_value)
);

CREATE INDEX IF NOT EXISTS idx_software_identifier_type_value
    ON platform.software_identifiers (id_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_software_identifier_identity
    ON platform.software_identifiers (software_identity_id);

CREATE TABLE IF NOT EXISTS platform.cpe_dim (
    id uuid PRIMARY KEY,
    raw_cpe varchar(1200) NOT NULL,
    normalized_cpe varchar(1200) NOT NULL,
    part varchar(500) NOT NULL,
    vendor varchar(500) NOT NULL,
    product varchar(500) NOT NULL,
    version varchar(500),
    update varchar(500),
    edition varchar(500),
    language varchar(500),
    sw_edition varchar(500),
    target_sw varchar(500),
    target_hw varchar(500),
    other varchar(500),
    cpe_key varchar(1000) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_cpe_dim_normalized UNIQUE (normalized_cpe)
);

CREATE INDEX IF NOT EXISTS idx_cpe_dim_key ON platform.cpe_dim (cpe_key);
CREATE INDEX IF NOT EXISTS idx_cpe_dim_normalized ON platform.cpe_dim (normalized_cpe);

CREATE TABLE IF NOT EXISTS platform.vulnerability_intel_summary (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL,
    external_id varchar(255) NOT NULL,
    title varchar(255) NOT NULL,
    description_snippet varchar(220),
    severity varchar(255) NOT NULL,
    cvss_score double precision,
    epss_score double precision,
    in_kev boolean NOT NULL,
    vuln_status varchar(255),
    source_count integer NOT NULL,
    published_at timestamptz,
    last_modified_at timestamptz,
    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    summary_updated_at timestamptz NOT NULL,
    CONSTRAINT uk_vulnerability_intel_summary_vulnerability UNIQUE (vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_vintel_summary_external_id
    ON platform.vulnerability_intel_summary (external_id);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_external_cvss_lastmod_updated
    ON platform.vulnerability_intel_summary (external_id, cvss_score, last_modified_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_cvss_lastmod_updated
    ON platform.vulnerability_intel_summary (cvss_score, last_modified_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_severity
    ON platform.vulnerability_intel_summary (severity);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_vuln_status
    ON platform.vulnerability_intel_summary (vuln_status);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_in_kev
    ON platform.vulnerability_intel_summary (in_kev);

CREATE TABLE IF NOT EXISTS platform.vulnerability_intel_observations (
    id uuid PRIMARY KEY,
    vulnerability_id uuid,
    source_system varchar(80) NOT NULL,
    source_record_id varchar(255) NOT NULL,
    source_url varchar(1200),
    title varchar(255),
    description text,
    severity varchar(40),
    cvss_score double precision,
    cvss_vector varchar(300),
    epss_score double precision,
    in_kev boolean,
    vuln_status varchar(120),
    cwe_ids varchar(2000),
    references_json text,
    source_identifier varchar(255),
    published_at timestamptz,
    last_modified_at timestamptz,
    raw_payload text,
    payload_hash varchar(128),
    observed_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_vulnerability_intel_observations_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT uk_vuln_intel_observation_source_record
        UNIQUE (source_system, source_record_id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_vulnerability
    ON platform.vulnerability_intel_observations (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_source
    ON platform.vulnerability_intel_observations (source_system);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_vuln_source
    ON platform.vulnerability_intel_observations (vulnerability_id, source_system);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_source_record
    ON platform.vulnerability_intel_observations (source_system, source_record_id);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_last_seen
    ON platform.vulnerability_intel_observations (last_seen_at);

CREATE TABLE IF NOT EXISTS platform.vulnerability_targets (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL,
    software_identity_id uuid,
    target_type varchar(40) NOT NULL,
    raw_target varchar(1200),
    normalized_target_key varchar(500) NOT NULL,
    ecosystem varchar(120),
    namespace varchar(120),
    package_name varchar(220),
    repo_url varchar(1200),
    version_exact varchar(255),
    version_start varchar(255),
    start_inclusive boolean,
    version_end varchar(255),
    end_inclusive boolean,
    introduced varchar(255),
    fixed varchar(255),
    version_scheme varchar(40) NOT NULL,
    constraint_type varchar(40),
    cpe varchar(1200),
    cpe_wildcard_score integer,
    cpe_id uuid,
    qualifier_part varchar(40),
    qualifier_vendor varchar(255),
    qualifier_product varchar(255),
    qualifier_version varchar(255),
    qualifier_update varchar(255),
    qualifier_edition varchar(255),
    qualifier_language varchar(255),
    qualifier_sw_edition varchar(255),
    qualifier_target_sw varchar(255),
    qualifier_target_hw varchar(255),
    qualifier_other varchar(255),
    qualifiers_json text,
    source varchar(80) NOT NULL,
    kb_version varchar(120),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_vulnerability_targets_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT fk_vulnerability_targets_software_identity
        FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT fk_vulnerability_targets_cpe
        FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim (id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_target_vuln
    ON platform.vulnerability_targets (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_target_type_key
    ON platform.vulnerability_targets (target_type, normalized_target_key);
CREATE INDEX IF NOT EXISTS idx_vuln_target_package
    ON platform.vulnerability_targets (package_name);
CREATE INDEX IF NOT EXISTS idx_vuln_target_identity
    ON platform.vulnerability_targets (software_identity_id);
CREATE INDEX IF NOT EXISTS idx_vuln_target_cpe_id
    ON platform.vulnerability_targets (cpe_id);
CREATE INDEX IF NOT EXISTS idx_vuln_target_type_cpe_id
    ON platform.vulnerability_targets (target_type, cpe_id);

CREATE TABLE IF NOT EXISTS platform.vex_assertions (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL,
    observation_id uuid,
    target_id uuid NOT NULL,
    software_identity_id uuid,
    cpe_id uuid,
    source_system varchar(80) NOT NULL,
    provider varchar(120) NOT NULL,
    document_id varchar(255) NOT NULL,
    statement_key varchar(512) NOT NULL,
    status varchar(64) NOT NULL,
    trust_tier varchar(40) NOT NULL,
    freshness varchar(40) NOT NULL,
    ecosystem varchar(120),
    namespace varchar(120),
    package_name varchar(220),
    normalized_product_key varchar(500) NOT NULL,
    version_exact varchar(255),
    version_start varchar(255),
    start_inclusive boolean,
    version_end varchar(255),
    end_inclusive boolean,
    fixed_version varchar(255),
    raw_target text,
    evidence_json text,
    published_at timestamptz,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_vex_assertions_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT fk_vex_assertions_observation
        FOREIGN KEY (observation_id) REFERENCES platform.vulnerability_intel_observations (id),
    CONSTRAINT fk_vex_assertions_target
        FOREIGN KEY (target_id) REFERENCES platform.vulnerability_targets (id),
    CONSTRAINT fk_vex_assertions_identity
        FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT fk_vex_assertions_cpe
        FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim (id),
    CONSTRAINT uk_vex_assertions_target UNIQUE (target_id),
    CONSTRAINT uk_vex_assertions_statement
        UNIQUE (vulnerability_id, source_system, document_id, statement_key)
);

CREATE INDEX IF NOT EXISTS idx_vex_assertions_vulnerability
    ON platform.vex_assertions (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_source
    ON platform.vex_assertions (source_system);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_target
    ON platform.vex_assertions (target_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_identity
    ON platform.vex_assertions (software_identity_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_cpe
    ON platform.vex_assertions (cpe_id);

CREATE TABLE IF NOT EXISTS platform.eol_product_catalog (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    slug varchar(200) NOT NULL,
    cpe_vendor varchar(200),
    cpe_product varchar(200),
    purl_type varchar(100),
    purl_namespace varchar(200),
    display_name varchar(200),
    aliases text,
    last_modified varchar(50),
    last_fetched_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_eol_product_catalog_slug UNIQUE (slug)
);

CREATE INDEX IF NOT EXISTS idx_eol_catalog_cpe
    ON platform.eol_product_catalog (cpe_vendor, cpe_product);
CREATE INDEX IF NOT EXISTS idx_eol_catalog_purl
    ON platform.eol_product_catalog (purl_type, purl_namespace);

CREATE TABLE IF NOT EXISTS platform.eol_release (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    product_slug varchar(200) NOT NULL,
    cycle varchar(100) NOT NULL,
    release_date date,
    eol_date date,
    eol_boolean boolean,
    support_end_date date,
    extended_support_date date,
    latest_version varchar(100),
    latest_release_date date,
    is_lts boolean NOT NULL,
    is_eol boolean NOT NULL,
    is_eoas boolean,
    is_eoes boolean,
    security_support_date date,
    official_source_url varchar(500),
    support_phase varchar(30),
    discontinued boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_eol_release_slug_cycle UNIQUE (product_slug, cycle)
);

CREATE INDEX IF NOT EXISTS idx_eol_release_product_slug
    ON platform.eol_release (product_slug);
CREATE INDEX IF NOT EXISTS idx_eol_release_is_eol
    ON platform.eol_release (is_eol);

CREATE TABLE IF NOT EXISTS platform.software_eol_mapping (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    software_identity_id uuid,
    normalized_key varchar(500) NOT NULL,
    eol_slug varchar(200),
    match_confidence varchar(20),
    match_method varchar(50),
    confirmed boolean NOT NULL,
    confirmed_by varchar(200),
    confirmed_at timestamptz,
    previous_slug varchar(200),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_software_eol_mapping_normalized_key UNIQUE (normalized_key)
);

CREATE INDEX IF NOT EXISTS idx_software_eol_mapping_identity
    ON platform.software_eol_mapping (software_identity_id);
CREATE INDEX IF NOT EXISTS idx_software_eol_mapping_slug
    ON platform.software_eol_mapping (eol_slug);

CREATE TABLE IF NOT EXISTS platform.identity_links (
    id uuid PRIMARY KEY,
    confidence double precision,
    created_at timestamptz NOT NULL,
    from_identifier_id uuid,
    last_seen_at timestamptz,
    link_type varchar(80) NOT NULL,
    match_rule varchar(40),
    provenance_note varchar(500),
    source varchar(80) NOT NULL,
    source_id varchar(255),
    source_type varchar(80),
    target_id varchar(255),
    target_type varchar(80),
    to_identifier_id uuid,
    updated_at timestamptz NOT NULL,
    verified boolean NOT NULL,
    verified_at timestamptz,
    verified_by varchar(255),
    CONSTRAINT fk_identity_links_from_identifier
        FOREIGN KEY (from_identifier_id) REFERENCES platform.software_identifiers (id),
    CONSTRAINT fk_identity_links_to_identifier
        FOREIGN KEY (to_identifier_id) REFERENCES platform.software_identifiers (id),
    CONSTRAINT uk_identity_links_pair_type_source
        UNIQUE (from_identifier_id, to_identifier_id, link_type, source)
);

CREATE INDEX IF NOT EXISTS idx_identity_links_from
    ON platform.identity_links (from_identifier_id);
CREATE INDEX IF NOT EXISTS idx_identity_links_to
    ON platform.identity_links (to_identifier_id);

CREATE TABLE IF NOT EXISTS platform.vulnerability_intel_summary_sources (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL,
    source_system varchar(80) NOT NULL,
    CONSTRAINT uk_vintel_summary_source_vuln_source
        UNIQUE (vulnerability_id, source_system)
);

CREATE INDEX IF NOT EXISTS idx_vintel_summary_source_vuln
    ON platform.vulnerability_intel_summary_sources (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_source_source
    ON platform.vulnerability_intel_summary_sources (source_system);
CREATE INDEX IF NOT EXISTS idx_vintel_summary_source_vuln_source
    ON platform.vulnerability_intel_summary_sources (vulnerability_id, source_system);

CREATE TABLE IF NOT EXISTS platform.vulnerability_intel_relations (
    id uuid PRIMARY KEY,
    confidence double precision,
    created_at timestamptz NOT NULL,
    from_observation_id uuid NOT NULL,
    provenance_note varchar(500),
    relation_type varchar(80) NOT NULL,
    source_system varchar(80) NOT NULL,
    to_observation_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    verified boolean NOT NULL,
    CONSTRAINT fk_vulnerability_intel_relations_from
        FOREIGN KEY (from_observation_id) REFERENCES platform.vulnerability_intel_observations (id),
    CONSTRAINT fk_vulnerability_intel_relations_to
        FOREIGN KEY (to_observation_id) REFERENCES platform.vulnerability_intel_observations (id),
    CONSTRAINT uk_vuln_intel_relations_pair_type_source
        UNIQUE (from_observation_id, to_observation_id, relation_type, source_system)
);

CREATE INDEX IF NOT EXISTS idx_vuln_intel_relations_from
    ON platform.vulnerability_intel_relations (from_observation_id);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_relations_to
    ON platform.vulnerability_intel_relations (to_observation_id);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_relations_type
    ON platform.vulnerability_intel_relations (relation_type);
CREATE INDEX IF NOT EXISTS idx_vuln_intel_relations_source
    ON platform.vulnerability_intel_relations (source_system);

CREATE TABLE IF NOT EXISTS platform.vulnerability_rules (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    cpe varchar(255),
    cpe_product varchar(255),
    cpe_vendor varchar(255),
    ecosystem varchar(255) NOT NULL,
    package_name varchar(255) NOT NULL,
    version_exact varchar(255),
    version_start varchar(255),
    version_start_inclusive boolean,
    version_end varchar(255),
    version_end_inclusive boolean,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT fk_vulnerability_rules_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_rules_vulnerability
    ON platform.vulnerability_rules (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_rules_ecosystem_package
    ON platform.vulnerability_rules (ecosystem, package_name);

CREATE TABLE IF NOT EXISTS platform.vulnerability_config_expr (
    id uuid PRIMARY KEY,
    child_node_count integer,
    config_index integer NOT NULL,
    created_at timestamptz NOT NULL,
    expr_json text,
    match_criteria_count integer,
    negate boolean NOT NULL,
    node_path varchar(1000) NOT NULL,
    operator varchar(32),
    parent_path varchar(1000),
    source varchar(40) NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT fk_vulnerability_config_expr_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_cfg_expr_vuln
    ON platform.vulnerability_config_expr (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_cfg_expr_source_cfg
    ON platform.vulnerability_config_expr (source, config_index);

CREATE TABLE IF NOT EXISTS tenant_default.assets (
    id uuid PRIMARY KEY,
    assigned_to varchar(255),
    base_image_digest varchar(255),
    business_criticality varchar(255) NOT NULL,
    cloud_account_id varchar(255),
    cloud_arn varchar(255),
    cloud_availability_zone varchar(255),
    cloud_instance_type varchar(255),
    cloud_launch_time timestamptz,
    cloud_provider varchar(255),
    cloud_region varchar(255),
    cloud_resource_type varchar(255),
    cloud_subnet_id varchar(255),
    cloud_tags_json varchar(255),
    cloud_vpc_id varchar(255),
    created_at timestamptz NOT NULL,
    department varchar(255),
    environment varchar(255),
    identifier varchar(255) NOT NULL,
    image_digest varchar(255),
    image_repository varchar(255),
    image_tag varchar(255),
    last_cmdb_sync_at timestamptz,
    last_inventory_at timestamptz,
    managed_by varchar(255),
    missing_iam_instance_profile boolean,
    name varchar(255) NOT NULL,
    owner_email varchar(255),
    owner_team varchar(255),
    service_name varchar(255),
    ssm_inventory_available boolean,
    ssm_inventory_last_captured_at timestamptz,
    ssm_last_ping_at timestamptz,
    ssm_managed boolean,
    ssm_ping_status varchar(255),
    state varchar(255) NOT NULL,
    support_group varchar(255),
    type varchar(255) NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT assets_business_criticality_check CHECK (business_criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT assets_state_check CHECK (state IN ('ACTIVE', 'INACTIVE', 'RETIRED', 'DECOMMISSIONED')),
    CONSTRAINT assets_type_check CHECK (type IN ('APPLICATION', 'HOST', 'CONTAINER_IMAGE', 'CLOUD_RESOURCE')),
    CONSTRAINT fk_assets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_assets_tenant_identifier UNIQUE (tenant_id, identifier)
);

CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON tenant_default.assets (tenant_id);

CREATE TABLE IF NOT EXISTS tenant_default.sbom_uploads (
    id uuid PRIMARY KEY,
    asset_id uuid,
    component_count integer,
    content_length_bytes bigint,
    content_sha256 varchar(255),
    content_type varchar(255),
    evidence_json text,
    fetch_status_code integer,
    findings_generated integer,
    format varchar(255) NOT NULL,
    ingestion_source_system varchar(255),
    ingestion_source_type varchar(255),
    original_filename varchar(255) NOT NULL,
    source_endpoint varchar(255),
    source_reference varchar(255),
    status varchar(255) NOT NULL,
    uploaded_at timestamptz NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT sbom_uploads_format_check CHECK (format IN ('CYCLONEDX', 'SPDX', 'HOST_INVENTORY', 'UNKNOWN')),
    CONSTRAINT sbom_uploads_status_check CHECK (status IN ('IN_PROGRESS', 'SUCCESS', 'FAILURE')),
    CONSTRAINT fk_sbom_uploads_asset FOREIGN KEY (asset_id) REFERENCES tenant_default.assets (id),
    CONSTRAINT fk_sbom_uploads_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_sbom_upload_asset_uploaded
    ON tenant_default.sbom_uploads (asset_id, uploaded_at);
CREATE INDEX IF NOT EXISTS idx_sbom_upload_tenant_uploaded
    ON tenant_default.sbom_uploads (tenant_id, uploaded_at);

CREATE TABLE IF NOT EXISTS tenant_default.inventory_components (
    id uuid PRIMARY KEY,
    component_digest varchar(255),
    component_status varchar(255) NOT NULL,
    coord_key varchar(255),
    ecosystem varchar(255) NOT NULL,
    eol_checked_at timestamptz,
    eol_cycle varchar(255),
    eol_date date,
    eol_slug varchar(255),
    eol_support_end_date date,
    ingested_at timestamptz NOT NULL,
    is_eol boolean,
    last_observed_at timestamptz NOT NULL,
    normalized_name varchar(255),
    normalized_purl varchar(255),
    normalized_version varchar(255),
    package_name varchar(255) NOT NULL,
    purl varchar(255) NOT NULL,
    retired_at timestamptz,
    support_phase varchar(255),
    version varchar(255),
    asset_id uuid NOT NULL,
    sbom_upload_id uuid NOT NULL,
    software_identity_id uuid,
    manual_identity_id uuid,
    manual_identity_reason varchar(400),
    manual_identity_confirmed_by varchar(255),
    manual_identity_confirmed_at timestamptz,
    tenant_id uuid NOT NULL,
    CONSTRAINT inventory_components_component_status_check CHECK (component_status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT fk_inventory_components_asset FOREIGN KEY (asset_id) REFERENCES tenant_default.assets (id),
    CONSTRAINT fk_inventory_components_sbom_upload FOREIGN KEY (sbom_upload_id) REFERENCES tenant_default.sbom_uploads (id),
    CONSTRAINT fk_inventory_components_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT fk_inventory_components_manual_identity FOREIGN KEY (manual_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT fk_inventory_components_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_inventory_tenant_asset ON tenant_default.inventory_components (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_inventory_sbom_upload ON tenant_default.inventory_components (sbom_upload_id);
CREATE INDEX IF NOT EXISTS idx_inventory_software_identity ON tenant_default.inventory_components (software_identity_id);
CREATE INDEX IF NOT EXISTS idx_inventory_component_digest ON tenant_default.inventory_components (component_digest);
CREATE INDEX IF NOT EXISTS idx_inventory_coord_key_tenant ON tenant_default.inventory_components (tenant_id, coord_key);
CREATE INDEX IF NOT EXISTS idx_inventory_norm_purl_tenant ON tenant_default.inventory_components (tenant_id, normalized_purl);

CREATE TABLE IF NOT EXISTS tenant_default.discovery_models (
    id uuid PRIMARY KEY,
    approved boolean,
    created_at timestamptz NOT NULL,
    display_name varchar(500),
    full_version varchar(255),
    language varchar(120),
    low_confidence boolean,
    ml_model_version varchar(120),
    normalization_status varchar(80),
    normalized_product varchar(255),
    normalized_publisher varchar(255),
    normalized_version varchar(255),
    platform varchar(120),
    primary_key varchar(500) NOT NULL,
    product_hash varchar(255),
    updated_at timestamptz NOT NULL,
    version_hash varchar(255),
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_discovery_models_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_discovery_models_tenant_primary_key UNIQUE (tenant_id, primary_key)
);

CREATE INDEX IF NOT EXISTS idx_discovery_models_product_hash
    ON tenant_default.discovery_models (product_hash);
CREATE INDEX IF NOT EXISTS idx_discovery_models_version_hash
    ON tenant_default.discovery_models (version_hash);

CREATE TABLE IF NOT EXISTS tenant_default.demo_requests (
    id uuid PRIMARY KEY,
    company varchar(255) NOT NULL,
    company_size varchar(80),
    decided_at timestamptz,
    decided_by varchar(255),
    email varchar(255) NOT NULL,
    full_name varchar(255) NOT NULL,
    notes varchar(2000),
    rejection_reason varchar(255),
    requested_at timestamptz NOT NULL,
    role_title varchar(255),
    status varchar(32) NOT NULL,
    tenant_id uuid,
    use_case varchar(120)
);

CREATE TABLE IF NOT EXISTS tenant_default.demo_invites (
    id uuid PRIMARY KEY,
    token varchar(96) NOT NULL,
    email varchar(255) NOT NULL,
    status varchar(32) NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    last_sent_at timestamptz,
    request_id uuid,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_demo_invites_request
        FOREIGN KEY (request_id) REFERENCES tenant_default.demo_requests (id),
    CONSTRAINT fk_demo_invites_tenant
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_demo_invites_token UNIQUE (token)
);

CREATE TABLE IF NOT EXISTS tenant_default.audit_events (
    id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_subject varchar(255) NOT NULL,
    actor_role varchar(64),
    action varchar(160) NOT NULL,
    target_type varchar(120),
    target_id varchar(255),
    request_id varchar(120),
    source_ip varchar(80),
    outcome varchar(32) NOT NULL,
    details_json jsonb,
    actor_user_id uuid,
    tenant_id uuid,
    CONSTRAINT fk_audit_events_actor_user FOREIGN KEY (actor_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.applicability_assessments (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    affected_components text,
    assessed_by varchar(100),
    attack_vector_accessible boolean,
    completed_at timestamptz,
    confidence_level varchar(20),
    configuration_details text,
    created_at timestamptz NOT NULL,
    current_version varchar(100),
    detection_method varchar(100),
    final_result varchar(50),
    fixed_version varchar(100),
    justification text,
    recommended_action text,
    software_detected boolean,
    status varchar(50) NOT NULL,
    updated_at timestamptz NOT NULL,
    vulnerable_configuration boolean,
    vulnerable_version_present boolean,
    vulnerable_version_range varchar(200),
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT fk_applicability_assessments_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_applicability_assessments_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.investigations (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    assigned_to varchar(100),
    business_impact text,
    closed_at timestamptz,
    created_at timestamptz NOT NULL,
    created_by varchar(100),
    exploit_available boolean,
    exploit_details text,
    mitigation_steps text,
    modified_by varchar(100),
    notes text,
    patch_available boolean,
    patch_details text,
    priority varchar(20),
    status varchar(50) NOT NULL,
    systems_affected text,
    updated_at timestamptz NOT NULL,
    vuln_references text,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT fk_investigations_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_investigations_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.investigation_activities (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    activity_type varchar(50) NOT NULL,
    created_at timestamptz NOT NULL,
    description text,
    metadata text,
    performed_by varchar(100),
    investigation_id bigint NOT NULL,
    CONSTRAINT fk_investigation_activities_investigation
        FOREIGN KEY (investigation_id) REFERENCES tenant_default.investigations (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.investigation_attachments (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    file_name varchar(255) NOT NULL,
    file_size bigint,
    file_type varchar(100),
    storage_path varchar(500) NOT NULL,
    uploaded_at timestamptz NOT NULL,
    uploaded_by varchar(100),
    investigation_id bigint NOT NULL,
    CONSTRAINT fk_investigation_attachments_investigation
        FOREIGN KEY (investigation_id) REFERENCES tenant_default.investigations (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.cis (
    id uuid PRIMARY KEY,
    assigned_to varchar(255),
    business_criticality varchar(32) NOT NULL,
    created_at timestamptz NOT NULL,
    department varchar(255),
    display_name varchar(255) NOT NULL,
    environment varchar(64),
    last_cmdb_sync_at timestamptz,
    last_inventory_at timestamptz,
    managed_by varchar(255),
    owner_email varchar(255),
    support_group varchar(255),
    sys_id varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    asset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_cis_asset FOREIGN KEY (asset_id) REFERENCES tenant_default.assets (id),
    CONSTRAINT fk_cis_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_cis_tenant_sys_id UNIQUE (tenant_id, sys_id),
    CONSTRAINT uk_cis_asset_id UNIQUE (asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cis_tenant_display
    ON tenant_default.cis (tenant_id, display_name);
CREATE INDEX IF NOT EXISTS idx_cis_tenant_env
    ON tenant_default.cis (tenant_id, environment);

CREATE TABLE IF NOT EXISTS tenant_default.ci_aliases (
    id uuid PRIMARY KEY,
    alias_name varchar(255) NOT NULL,
    confidence double precision,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    normalized_alias_name varchar(255) NOT NULL,
    source_system varchar(64) NOT NULL,
    ci_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_ci_aliases_ci FOREIGN KEY (ci_id) REFERENCES tenant_default.cis (id),
    CONSTRAINT fk_ci_aliases_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_ci_aliases_tenant_alias_source UNIQUE (tenant_id, normalized_alias_name, source_system)
);

CREATE INDEX IF NOT EXISTS idx_ci_aliases_tenant_alias
    ON tenant_default.ci_aliases (tenant_id, normalized_alias_name);
CREATE INDEX IF NOT EXISTS idx_ci_aliases_ci
    ON tenant_default.ci_aliases (ci_id);

CREATE TABLE IF NOT EXISTS tenant_default.software_instances (
    id uuid PRIMARY KEY,
    active_install boolean,
    created_at timestamptz NOT NULL,
    discovery_model_pk varchar(500),
    display_name varchar(500) NOT NULL,
    eol_checked_at timestamptz,
    eol_cycle varchar(100),
    eol_date date,
    eol_slug varchar(200),
    eol_support_end_date date,
    install_date timestamptz,
    is_eol boolean,
    last_scanned timestamptz,
    last_used timestamptz,
    normalized_product varchar(255) NOT NULL,
    normalized_publisher varchar(255),
    normalized_version varchar(255),
    publisher varchar(255),
    source_system varchar(64) NOT NULL,
    support_phase varchar(30),
    unlicensed_install boolean,
    updated_at timestamptz NOT NULL,
    version varchar(255),
    version_evidence varchar(1000),
    ci_id uuid NOT NULL,
    discovery_model_id uuid,
    inventory_component_id uuid,
    software_identity_id uuid,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_software_instances_ci FOREIGN KEY (ci_id) REFERENCES tenant_default.cis (id),
    CONSTRAINT fk_software_instances_discovery_model FOREIGN KEY (discovery_model_id) REFERENCES tenant_default.discovery_models (id),
    CONSTRAINT fk_software_instances_inventory_component FOREIGN KEY (inventory_component_id) REFERENCES tenant_default.inventory_components (id),
    CONSTRAINT fk_software_instances_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id),
    CONSTRAINT fk_software_instances_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_software_instances_ci_product_version_evidence
        UNIQUE (ci_id, normalized_product, normalized_version, version_evidence)
);

CREATE INDEX IF NOT EXISTS idx_software_instances_ci
    ON tenant_default.software_instances (ci_id);
CREATE INDEX IF NOT EXISTS idx_software_instances_identity
    ON tenant_default.software_instances (software_identity_id);
CREATE INDEX IF NOT EXISTS idx_software_instances_discovery_model
    ON tenant_default.software_instances (discovery_model_id);

CREATE TABLE IF NOT EXISTS tenant_default.software_inventory_items (
    id uuid PRIMARY KEY,
    component_status varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    ecosystem varchar(255) NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_observed_at timestamptz,
    package_name varchar(255) NOT NULL,
    purl varchar(255) NOT NULL,
    synced_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version varchar(255) NOT NULL,
    asset_id uuid,
    component_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_software_inventory_items_asset FOREIGN KEY (asset_id) REFERENCES tenant_default.assets (id),
    CONSTRAINT fk_software_inventory_items_component FOREIGN KEY (component_id) REFERENCES tenant_default.inventory_components (id),
    CONSTRAINT fk_software_inventory_items_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_software_inventory_tenant_component UNIQUE (tenant_id, component_id)
);

CREATE INDEX IF NOT EXISTS idx_software_inventory_tenant_component
    ON tenant_default.software_inventory_items (tenant_id, component_id);
CREATE INDEX IF NOT EXISTS idx_software_inventory_tenant_status
    ON tenant_default.software_inventory_items (tenant_id, component_status);
CREATE INDEX IF NOT EXISTS idx_software_inventory_tenant_pkg
    ON tenant_default.software_inventory_items (tenant_id, ecosystem, package_name, version);

CREATE TABLE IF NOT EXISTS tenant_default.inventory_component_cpe_map (
    id uuid PRIMARY KEY,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    observed_version varchar(255),
    component_id uuid NOT NULL,
    cpe_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_inventory_component_cpe_map_component
        FOREIGN KEY (component_id) REFERENCES tenant_default.inventory_components (id),
    CONSTRAINT fk_inventory_component_cpe_map_cpe
        FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim (id),
    CONSTRAINT fk_inventory_component_cpe_map_tenant
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_inventory_component_cpe UNIQUE (tenant_id, component_id, cpe_id)
);

CREATE INDEX IF NOT EXISTS idx_iccm_tenant_cpe
    ON tenant_default.inventory_component_cpe_map (tenant_id, cpe_id);
CREATE INDEX IF NOT EXISTS idx_iccm_tenant_component
    ON tenant_default.inventory_component_cpe_map (tenant_id, component_id);

CREATE TABLE IF NOT EXISTS tenant_default.component_vulnerability_states (
    id uuid PRIMARY KEY,
    analyst_disposition varchar(40),
    analyst_reason text,
    analyst_updated_at timestamptz,
    analyst_updated_by varchar(255),
    applicability_reason varchar(255),
    applicability_reason_detail text,
    applicability_state varchar(40) NOT NULL,
    confidence_score double precision,
    created_at timestamptz NOT NULL,
    eligible_for_finding boolean NOT NULL,
    impact_reason varchar(255),
    impact_reason_detail text,
    impact_state varchar(40) NOT NULL,
    last_evaluated_at timestamptz NOT NULL,
    matched_by varchar(120),
    matched_vex_assertion_id uuid,
    precedence_reason varchar(120),
    selected_target_source varchar(255),
    state_changed_at timestamptz NOT NULL,
    trace_json text,
    updated_at timestamptz NOT NULL,
    vex_freshness varchar(40),
    vex_provider varchar(120),
    vex_source varchar(120),
    vex_status varchar(80),
    vex_target_id uuid,
    component_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT fk_component_vulnerability_states_component
        FOREIGN KEY (component_id) REFERENCES tenant_default.inventory_components (id),
    CONSTRAINT fk_component_vulnerability_states_tenant
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_component_vulnerability_states_vulnerability
        FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT uk_component_vuln_state_tenant_component_vulnerability
        UNIQUE (tenant_id, component_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_component_vuln
    ON tenant_default.component_vulnerability_states (tenant_id, component_id, vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_applicability
    ON tenant_default.component_vulnerability_states (tenant_id, applicability_state);
CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_impact
    ON tenant_default.component_vulnerability_states (tenant_id, impact_state);
CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_eligible
    ON tenant_default.component_vulnerability_states (tenant_id, eligible_for_finding);
CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_vuln_impact
    ON tenant_default.component_vulnerability_states (tenant_id, vulnerability_id, impact_state);
CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_impact_updated
    ON tenant_default.component_vulnerability_states (tenant_id, impact_state, updated_at);

CREATE TABLE IF NOT EXISTS tenant_default.github_sbom_sources (
    id uuid PRIMARY KEY,
    asset_identifier varchar(255) NOT NULL,
    asset_name varchar(255) NOT NULL,
    asset_type varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    enabled boolean NOT NULL,
    frequency varchar(255) NOT NULL,
    interval_minutes integer NOT NULL,
    last_error varchar(2000),
    last_run_at timestamptz,
    last_run_status varchar(64),
    name varchar(255) NOT NULL,
    owner varchar(255) NOT NULL,
    path varchar(1000) NOT NULL,
    repo varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid,
    CONSTRAINT fk_github_sbom_sources_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_github_sbom_sources_enabled
    ON tenant_default.github_sbom_sources (enabled, last_run_at);
CREATE INDEX IF NOT EXISTS idx_github_sbom_sources_tenant
    ON tenant_default.github_sbom_sources (tenant_id, enabled, created_at);

CREATE TABLE IF NOT EXISTS tenant_default.findings (
    id uuid PRIMARY KEY,
    assigned_at timestamptz,
    assigned_by varchar(255),
    assigned_to varchar(255),
    confidence_score double precision,
    auto_close_eligible_at timestamptz,
    closed_at timestamptz,
    closed_by varchar(255),
    closed_reason varchar(80),
    closed_rule_id uuid,
    consecutive_misses integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    creation_source varchar(255) NOT NULL,
    decision_state varchar(255),
    display_id varchar(16) NOT NULL,
    due_at timestamptz,
    evidence jsonb,
    first_observed_at timestamptz,
    incident_id varchar(64),
    incident_status varchar(64),
    last_observed_at timestamptz,
    last_observed_run_id uuid,
    matched_by varchar(255) NOT NULL,
    matched_vex_assertion_id uuid,
    owner_group varchar(255),
    precedence_trace text,
    risk_score double precision NOT NULL,
    severity_override varchar(16),
    status varchar(255) NOT NULL,
    suppressed_by_rule_id uuid,
    suppressed_by_rule_name varchar(255),
    suppressed_until timestamptz,
    suppression_reason varchar(2000),
    updated_at timestamptz NOT NULL,
    vex_freshness varchar(64),
    vex_provider varchar(128),
    vex_status varchar(64),
    asset_id uuid NOT NULL,
    component_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT findings_status_check CHECK (status IN ('OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED')),
    CONSTRAINT findings_decision_state_check CHECK (decision_state IN ('AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NEEDS_REVIEW')),
    CONSTRAINT findings_creation_source_check CHECK (creation_source IN ('MANUAL', 'AUTOMATIC')),
    CONSTRAINT fk_findings_asset FOREIGN KEY (asset_id) REFERENCES tenant_default.assets (id),
    CONSTRAINT fk_findings_component FOREIGN KEY (component_id) REFERENCES tenant_default.inventory_components (id),
    CONSTRAINT fk_findings_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_findings_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT uk_findings_component_vulnerability UNIQUE (component_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_status_updated
    ON tenant_default.findings (tenant_id, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_component_vuln
    ON tenant_default.findings (tenant_id, component_id, vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON tenant_default.findings (asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_id ON tenant_default.findings (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_status ON tenant_default.findings (vulnerability_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_vex_status ON tenant_default.findings (vex_status);
CREATE INDEX IF NOT EXISTS idx_findings_vex_freshness ON tenant_default.findings (vex_freshness);
CREATE INDEX IF NOT EXISTS idx_findings_vex_provider ON tenant_default.findings (vex_provider);
CREATE INDEX IF NOT EXISTS idx_findings_auto_close_eligible
    ON tenant_default.findings (tenant_id, status, auto_close_eligible_at);

CREATE TABLE IF NOT EXISTS tenant_default.finding_events (
    id uuid PRIMARY KEY,
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    details_json jsonb,
    event_type varchar(255) NOT NULL,
    summary varchar(255) NOT NULL,
    finding_id uuid NOT NULL,
    CONSTRAINT fk_finding_events_finding FOREIGN KEY (finding_id) REFERENCES tenant_default.findings (id)
);

CREATE INDEX IF NOT EXISTS idx_finding_events_finding_created
    ON tenant_default.finding_events (finding_id, created_at);

CREATE TABLE IF NOT EXISTS tenant_default.finding_comments (
    id uuid PRIMARY KEY,
    author varchar(255) NOT NULL,
    body varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    finding_id uuid NOT NULL,
    CONSTRAINT fk_finding_comments_finding FOREIGN KEY (finding_id) REFERENCES tenant_default.findings (id)
);

CREATE INDEX IF NOT EXISTS idx_finding_comments_finding_created
    ON tenant_default.finding_comments (finding_id, created_at);

CREATE TABLE IF NOT EXISTS tenant_default.finding_delta_queue (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    attempt_count integer NOT NULL DEFAULT 0,
    completed_at timestamptz,
    component_id uuid,
    dedupe_key varchar(700) NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    error_message text,
    event_type varchar(30) NOT NULL,
    max_attempts integer NOT NULL DEFAULT 3,
    processing_started_at timestamptz,
    source_key varchar(500),
    source_tag varchar(255),
    status varchar(20) NOT NULL DEFAULT 'PENDING',
    tenant_id uuid,
    visible_after timestamptz NOT NULL DEFAULT now(),
    vulnerability_id uuid
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fdq_dedupe_pending
    ON tenant_default.finding_delta_queue (dedupe_key)
    WHERE status = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_fdq_pending_visible
    ON tenant_default.finding_delta_queue (status, visible_after, id)
    WHERE status = 'PENDING';

CREATE TABLE IF NOT EXISTS tenant_default.risk_policies (
    id uuid PRIMARY KEY,
    asset_critical_sla_multiplier double precision NOT NULL,
    asset_high_sla_multiplier double precision NOT NULL,
    asset_low_sla_multiplier double precision NOT NULL,
    asset_medium_sla_multiplier double precision NOT NULL,
    auto_close_after_days integer NOT NULL,
    auto_close_asset_identifier varchar(255),
    auto_close_asset_retired_enabled boolean NOT NULL DEFAULT true,
    auto_close_component_removed_enabled boolean NOT NULL DEFAULT true,
    auto_close_duplicate_enabled boolean NOT NULL DEFAULT true,
    auto_close_enabled boolean NOT NULL,
    auto_close_not_observed_enabled boolean NOT NULL DEFAULT true,
    auto_close_required_consecutive_misses integer NOT NULL DEFAULT 2,
    auto_close_run_interval_days integer NOT NULL DEFAULT 1,
    auto_close_last_run_at timestamptz,
    auto_close_source_disabled_enabled boolean NOT NULL DEFAULT false,
    critical_sla_days integer NOT NULL,
    critical_threshold double precision NOT NULL,
    finding_generation_mode varchar(20) NOT NULL,
    findings_score_config jsonb,
    high_sla_days integer NOT NULL,
    high_threshold double precision NOT NULL,
    low_sla_days integer NOT NULL,
    medium_sla_days integer NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT risk_policies_finding_generation_mode_check CHECK (finding_generation_mode IN ('AUTO', 'MANUAL')),
    CONSTRAINT fk_risk_policies_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_risk_policies_tenant UNIQUE (tenant_id)
);

CREATE TABLE IF NOT EXISTS tenant_default.fix_records (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    cve_id varchar(255) NOT NULL,
    description text,
    fix_type varchar(255) NOT NULL,
    generated_at timestamptz NOT NULL,
    os_hint varchar(255),
    recommendation_source varchar(255) NOT NULL,
    related_cve_ids jsonb,
    software_entities jsonb,
    source_urls jsonb,
    summary varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_fix_records_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_fix_records_tenant_cve
    ON tenant_default.fix_records (tenant_id, cve_id);

CREATE TABLE IF NOT EXISTS platform.sync_runs (
    id uuid PRIMARY KEY,
    completed_at timestamptz,
    error_message varchar(2000),
    metadata_json text,
    records_failed integer NOT NULL,
    records_fetched integer NOT NULL,
    records_inserted integer NOT NULL,
    records_updated integer NOT NULL,
    run_scope varchar(64) NOT NULL,
    started_at timestamptz NOT NULL,
    status varchar(255) NOT NULL,
    sync_type varchar(255) NOT NULL,
    tenant_id uuid,
    CONSTRAINT fk_sync_runs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE INDEX IF NOT EXISTS idx_sync_runs_run_scope_started
    ON platform.sync_runs (run_scope, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant_started
    ON platform.sync_runs (tenant_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_sync_type_status
    ON platform.sync_runs (lower(sync_type), lower(status), started_at DESC);

CREATE TABLE IF NOT EXISTS tenant_default.service_accounts (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    key_id varchar(255) NOT NULL,
    last_used_at timestamptz,
    name varchar(255) NOT NULL,
    role varchar(255) NOT NULL,
    status varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid,
    CONSTRAINT fk_service_accounts_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_service_accounts_key_id UNIQUE (key_id)
);

CREATE TABLE IF NOT EXISTS tenant_default.org_cve_records (
    id uuid PRIMARY KEY,
    applicability_state varchar(255) NOT NULL,
    applicable_component_count bigint NOT NULL,
    created_at timestamptz NOT NULL,
    cvss_score double precision,
    eol_component_count bigint NOT NULL,
    eos_component_count bigint NOT NULL,
    epss_score double precision,
    external_id varchar(255) NOT NULL,
    fixed_component_count bigint NOT NULL,
    impact_reason varchar(255),
    impact_state varchar(255) NOT NULL,
    impacted boolean NOT NULL,
    impacted_component_count bigint NOT NULL,
    in_kev boolean NOT NULL,
    last_evaluated_at timestamptz NOT NULL,
    matched_asset_count bigint NOT NULL,
    matched_component_count bigint NOT NULL,
    matched_software_count bigint NOT NULL,
    no_patch_component_count bigint NOT NULL,
    not_affected_component_count bigint NOT NULL,
    org_impact varchar(255),
    review_reason varchar(255),
    severity varchar(255) NOT NULL,
    suppressed_at timestamptz,
    suppressed_by varchar(255),
    suppressed_by_rule_id uuid,
    suppressed_by_rule_name varchar(255),
    suppressed_until timestamptz,
    suppression_justification varchar(255),
    suppression_reason varchar(255),
    under_investigation_component_count bigint NOT NULL,
    unknown_component_count bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    vuln_status varchar(255),
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT org_cve_records_applicability_state_check CHECK (applicability_state IN ('APPLICABLE', 'NOT_APPLICABLE', 'UNKNOWN')),
    CONSTRAINT org_cve_records_impact_state_check CHECK (impact_state IN ('IMPACTED', 'NOT_IMPACTED', 'FIXED', 'NO_PATCH', 'UNDER_INVESTIGATION', 'UNKNOWN')),
    CONSTRAINT org_cve_records_org_impact_check CHECK (org_impact IN ('NONE', 'LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT fk_org_cve_records_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_org_cve_records_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities (id),
    CONSTRAINT uk_org_cve_record_tenant_vulnerability UNIQUE (tenant_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_applicability
    ON tenant_default.org_cve_records (tenant_id, applicability_state);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_external_id
    ON tenant_default.org_cve_records (tenant_id, external_id);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_impact_state
    ON tenant_default.org_cve_records (tenant_id, impact_state);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_impacted
    ON tenant_default.org_cve_records (tenant_id, impacted);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_rank
    ON tenant_default.org_cve_records (tenant_id, impacted, applicability_state, cvss_score, external_id);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_suppressed_until
    ON tenant_default.org_cve_records (tenant_id, suppressed_until);
CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_vulnerability
    ON tenant_default.org_cve_records (tenant_id, vulnerability_id);

CREATE TABLE IF NOT EXISTS tenant_default.org_cve_ai_artifacts (
    org_cve_record_id uuid PRIMARY KEY,
    ai_actions_generated_at timestamptz,
    ai_actions_json jsonb,
    ai_solution_generated_at timestamptz,
    ai_solution_json jsonb,
    created_at timestamptz NOT NULL,
    investigation_summary_generated_at timestamptz,
    investigation_summary_input_json jsonb,
    investigation_summary_mode varchar(255),
    investigation_summary_output_json jsonb,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_org_cve_ai_artifacts_org_cve_record
        FOREIGN KEY (org_cve_record_id) REFERENCES tenant_default.org_cve_records (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.ownership_rules (
    id uuid PRIMARY KEY,
    condition_json text NOT NULL,
    created_at timestamptz NOT NULL,
    execution_order integer NOT NULL,
    name varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    user_group varchar(255) NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_ownership_rules_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.suppression_rules (
    id uuid PRIMARY KEY,
    condition_logic varchar(255) NOT NULL,
    conditions_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    name varchar(255) NOT NULL,
    reason varchar(255),
    record_type varchar(255) NOT NULL,
    state varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    valid_from timestamptz,
    valid_to timestamptz,
    tenant_id uuid NOT NULL,
    CONSTRAINT suppression_rules_record_type_check CHECK (record_type IN ('CVE', 'FINDING')),
    CONSTRAINT suppression_rules_state_check CHECK (state IN ('DRAFT', 'APPROVED', 'IN_REVIEW', 'REJECTED', 'EXPIRED')),
    CONSTRAINT fk_suppression_rules_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

CREATE TABLE IF NOT EXISTS tenant_default.vulnerability_source_filter_configs (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    enabled_for_correlation boolean NOT NULL,
    filters_json text,
    source_system varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_vulnerability_source_filter_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_vulnerability_source_filter_configs_tenant_source UNIQUE (tenant_id, source_system)
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_source_filter_configs_tenant
    ON tenant_default.vulnerability_source_filter_configs (tenant_id);

CREATE TABLE IF NOT EXISTS tenant_default.aws_discovery_configs (
    id uuid PRIMARY KEY,
    access_key_id varchar(255),
    auth_type varchar(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    aws_account_id varchar(255),
    created_at timestamptz NOT NULL,
    credential_secret varchar(255),
    cross_account_role_arn varchar(255),
    enabled boolean NOT NULL,
    external_id varchar(255),
    interval_minutes integer NOT NULL,
    last_sync_at timestamptz,
    last_test_message varchar(255),
    last_test_status varchar(255),
    last_tested_at timestamptz,
    regions_json varchar(255) NOT NULL,
    resource_types_json varchar(255) NOT NULL,
    source_system varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT aws_discovery_configs_auth_type_check CHECK (auth_type IN ('INSTANCE_METADATA', 'ACCESS_KEY', 'CROSS_ACCOUNT_ROLE')),
    CONSTRAINT fk_aws_discovery_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_aws_discovery_configs_tenant_source UNIQUE (tenant_id, source_system)
);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_configs_enabled
    ON tenant_default.aws_discovery_configs (enabled, auto_sync_enabled);
CREATE INDEX IF NOT EXISTS idx_aws_discovery_configs_tenant
    ON tenant_default.aws_discovery_configs (tenant_id);

CREATE TABLE IF NOT EXISTS tenant_default.aws_discovery_targets (
    id uuid PRIMARY KEY,
    account_id varchar(255),
    account_name varchar(255),
    created_at timestamptz NOT NULL,
    enabled boolean NOT NULL,
    external_id varchar(255),
    last_sync_at timestamptz,
    last_test_message varchar(255),
    last_test_status varchar(255),
    last_tested_at timestamptz,
    regions_json varchar(255) NOT NULL,
    resource_types_json varchar(255) NOT NULL,
    role_arn varchar(255),
    updated_at timestamptz NOT NULL,
    config_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT fk_aws_discovery_targets_config FOREIGN KEY (config_id) REFERENCES tenant_default.aws_discovery_configs (id),
    CONSTRAINT fk_aws_discovery_targets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_aws_discovery_targets_config_account UNIQUE (config_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_aws_discovery_targets_config
    ON tenant_default.aws_discovery_targets (config_id);
CREATE INDEX IF NOT EXISTS idx_aws_discovery_targets_tenant_enabled
    ON tenant_default.aws_discovery_targets (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS tenant_default.sccm_cmdb_configs (
    id uuid PRIMARY KEY,
    auth_type varchar(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    credential_secret varchar(255),
    database_name varchar(255) NOT NULL,
    enabled boolean NOT NULL,
    fetch_size integer NOT NULL,
    interval_minutes integer NOT NULL,
    jdbc_url varchar(255),
    last_sync_at timestamptz,
    last_test_message varchar(255),
    last_test_status varchar(255),
    last_tested_at timestamptz,
    mock_mode boolean NOT NULL,
    query_timeout_seconds integer NOT NULL,
    site_code varchar(255),
    source_system varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    username varchar(255),
    tenant_id uuid NOT NULL,
    CONSTRAINT sccm_cmdb_configs_auth_type_check CHECK (auth_type IN ('SQL_AUTH', 'WINDOWS_AUTH')),
    CONSTRAINT fk_sccm_cmdb_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_sccm_cmdb_configs_tenant_source UNIQUE (tenant_id, source_system)
);

CREATE INDEX IF NOT EXISTS idx_sccm_cmdb_configs_enabled
    ON tenant_default.sccm_cmdb_configs (enabled, auto_sync_enabled);
CREATE INDEX IF NOT EXISTS idx_sccm_cmdb_configs_tenant
    ON tenant_default.sccm_cmdb_configs (tenant_id);

CREATE TABLE IF NOT EXISTS tenant_default.servicenow_cmdb_configs (
    id uuid PRIMARY KEY,
    auth_type varchar(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    base_url varchar(255),
    ci_table varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    credential_secret varchar(255),
    discovery_fields varchar(255),
    discovery_model_table varchar(255) NOT NULL,
    discovery_query varchar(255),
    enabled boolean NOT NULL,
    install_fields varchar(255),
    install_query varchar(255),
    install_table varchar(255) NOT NULL,
    interval_minutes integer NOT NULL,
    last_sync_at timestamptz,
    last_test_message varchar(255),
    last_test_status varchar(255),
    last_tested_at timestamptz,
    page_size integer NOT NULL,
    source_system varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL,
    username varchar(255),
    tenant_id uuid NOT NULL,
    CONSTRAINT servicenow_cmdb_configs_auth_type_check CHECK (auth_type IN ('BASIC', 'BEARER')),
    CONSTRAINT fk_servicenow_cmdb_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT uk_servicenow_cmdb_configs_tenant_source UNIQUE (tenant_id, source_system)
);

CREATE INDEX IF NOT EXISTS idx_servicenow_cmdb_configs_enabled
    ON tenant_default.servicenow_cmdb_configs (enabled, auto_sync_enabled);
CREATE INDEX IF NOT EXISTS idx_servicenow_cmdb_configs_tenant
    ON tenant_default.servicenow_cmdb_configs (tenant_id);

CREATE INDEX IF NOT EXISTS idx_inventory_components_manual_identity
    ON tenant_default.inventory_components (manual_identity_id)
    WHERE manual_identity_id IS NOT NULL;

-- Software identity summary projection (V1043)
CREATE TABLE IF NOT EXISTS tenant_default.software_identity_summary (
    tenant_id uuid NOT NULL,
    software_identity_id uuid NOT NULL,
    display_name text,
    canonical_key text,
    vendor text,
    product text,
    normalized_key text NOT NULL,
    purl text,
    cpe23 text,
    asset_types text[] NOT NULL DEFAULT '{}',
    ecosystems text[] NOT NULL DEFAULT '{}',
    source_systems text[] NOT NULL DEFAULT '{}',
    eol_slug text,
    mapping_confirmed boolean NOT NULL DEFAULT FALSE,
    needs_eol_mapping boolean NOT NULL DEFAULT FALSE,
    asset_count bigint NOT NULL DEFAULT 0,
    component_count bigint NOT NULL DEFAULT 0,
    version_count bigint NOT NULL DEFAULT 0,
    eol_component_count bigint NOT NULL DEFAULT 0,
    near_eol_component_count bigint NOT NULL DEFAULT 0,
    unknown_eol_component_count bigint NOT NULL DEFAULT 0,
    last_observed_at timestamptz,
    summary_updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, software_identity_id),
    CONSTRAINT fk_software_identity_summary_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_software_identity_summary_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id)
);

CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_component_count
    ON tenant_default.software_identity_summary (tenant_id, component_count DESC, display_name);
CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_mapping
    ON tenant_default.software_identity_summary (tenant_id, needs_eol_mapping, mapping_confirmed);
CREATE INDEX IF NOT EXISTS idx_software_identity_summary_tenant_lifecycle
    ON tenant_default.software_identity_summary (tenant_id, eol_component_count DESC, near_eol_component_count DESC, unknown_eol_component_count DESC);
CREATE INDEX IF NOT EXISTS idx_software_identity_summary_normalized_key
    ON tenant_default.software_identity_summary (normalized_key);

-- Data quality issue projection (V1044)
CREATE TABLE IF NOT EXISTS tenant_default.quality_issue_projection (
    id text PRIMARY KEY,
    tenant_id uuid NOT NULL,
    issue_key text NOT NULL,
    domain text NOT NULL,
    issue_type text NOT NULL,
    severity text NOT NULL,
    reason_code text NOT NULL,
    source_object_type text NOT NULL,
    source_object_id text,
    asset_id uuid,
    component_id uuid,
    software_identity_id uuid,
    vulnerability_id uuid,
    sync_run_id uuid,
    title text NOT NULL,
    primary_label text,
    secondary_label text,
    asset_type text,
    source_system text,
    ecosystem text,
    affects_active_findings boolean NOT NULL DEFAULT FALSE,
    affected_asset_count bigint NOT NULL DEFAULT 0,
    affected_component_count bigint NOT NULL DEFAULT 0,
    open_finding_count bigint NOT NULL DEFAULT 0,
    open_vulnerability_count bigint NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    last_computed_at timestamptz NOT NULL DEFAULT now(),
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    drilldown_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    CONSTRAINT uk_quality_issue_projection_tenant_issue UNIQUE (tenant_id, issue_key),
    CONSTRAINT fk_quality_issue_projection_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_domain
    ON tenant_default.quality_issue_projection (tenant_id, domain, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_filters
    ON tenant_default.quality_issue_projection (tenant_id, affects_active_findings, asset_type, source_system, ecosystem);
CREATE INDEX IF NOT EXISTS idx_quality_issue_projection_refs
    ON tenant_default.quality_issue_projection (tenant_id, vulnerability_id, software_identity_id, component_id, asset_id);

-- Dashboard noise reduction projection (V1045)
CREATE TABLE IF NOT EXISTS tenant_default.dashboard_noise_reduction_projection (
    tenant_id uuid PRIMARY KEY,
    never_opened_not_applicable bigint NOT NULL DEFAULT 0,
    deferred_under_investigation bigint NOT NULL DEFAULT 0,
    category_counts_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_computed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_dashboard_noise_reduction_projection_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dashboard_noise_reduction_projection_last_computed
    ON tenant_default.dashboard_noise_reduction_projection (last_computed_at DESC);

-- Software identity cluster link for bulk normalization overrides (V1059)
CREATE TABLE IF NOT EXISTS tenant_default.software_identity_cluster_link (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    source_type varchar(40) NOT NULL,
    source_key varchar(500) NOT NULL,
    target_identity_id uuid NOT NULL,
    apply_to_future boolean NOT NULL DEFAULT TRUE,
    reason varchar(400),
    confirmed_by varchar(255),
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by varchar(255),
    CONSTRAINT fk_software_identity_cluster_link_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_software_identity_cluster_link_identity FOREIGN KEY (target_identity_id) REFERENCES platform.software_identities (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cluster_link_active
    ON tenant_default.software_identity_cluster_link (tenant_id, source_type, source_key)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_cluster_link_tenant
    ON tenant_default.software_identity_cluster_link (tenant_id)
    WHERE revoked_at IS NULL;

-- Investigation runbook state + agent/copilot config (Phase 2+3)

CREATE TABLE IF NOT EXISTS tenant_default.investigation_runbook (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL
                            REFERENCES platform.tenants(id),
    cve_external_id     VARCHAR(50) NOT NULL,
    task_states         JSONB NOT NULL DEFAULT '[]',
    agent_suggestions   JSONB NOT NULL DEFAULT '{}',
    fp_overrides        JSONB NOT NULL DEFAULT '[]',
    log_entries         JSONB NOT NULL DEFAULT '[]',
    lead_analyst        VARCHAR(100),
    agent_confidence    JSONB,
    agent_run_meta      JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_runbook_tenant_cve UNIQUE (tenant_id, cve_external_id)
);

CREATE INDEX IF NOT EXISTS idx_runbook_tenant_id
    ON tenant_default.investigation_runbook(tenant_id);
CREATE INDEX IF NOT EXISTS idx_runbook_cve_external_id
    ON tenant_default.investigation_runbook(cve_external_id);

ALTER TABLE tenant_default.risk_policies
    ADD COLUMN IF NOT EXISTS copilot_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS copilot_shadow_mode        BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS copilot_auto_run           BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS agent_auto_threshold       DOUBLE PRECISION NOT NULL DEFAULT 0.85,
    ADD COLUMN IF NOT EXISTS agent_review_threshold     DOUBLE PRECISION NOT NULL DEFAULT 0.60,
    ADD COLUMN IF NOT EXISTS agent_max_concurrent       INTEGER NOT NULL DEFAULT 10;


-- source: V2__finding_queue_personalization.sql
CREATE TABLE IF NOT EXISTS platform.personal_finding_queues (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    queue_key varchar(120) NOT NULL,
    title varchar(160) NOT NULL,
    description varchar(500),
    filter_json text NOT NULL,
    display_order integer NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_personal_finding_queues_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_personal_finding_queues_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_personal_finding_queues_owner_key UNIQUE (tenant_id, owner_user_id, queue_key),
    CONSTRAINT uk_personal_finding_queues_owner_title UNIQUE (tenant_id, owner_user_id, title)
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_personal_finding_queues_owner_default
    ON platform.personal_finding_queues (tenant_id, owner_user_id)
    WHERE is_default = true;

CREATE INDEX IF NOT EXISTS idx_personal_finding_queues_owner_order
    ON platform.personal_finding_queues (tenant_id, owner_user_id, display_order, created_at);

CREATE TABLE IF NOT EXISTS platform.finding_queue_preferences (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    default_queue_ref varchar(160) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_finding_queue_preferences_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_finding_queue_preferences_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_finding_queue_preferences_owner UNIQUE (tenant_id, owner_user_id)
);


-- source: V3__finding_workspace_projection.sql
CREATE TABLE IF NOT EXISTS finding_list_projection (
    finding_id uuid PRIMARY KEY,
    display_id varchar(32),
    severity varchar(32),
    status varchar(32) NOT NULL,
    decision_state varchar(64),
    creation_source varchar(32),
    match_method varchar(64),
    vex_status varchar(64),
    vex_freshness varchar(64),
    vex_provider varchar(128),
    confidence_score double precision,
    vulnerability_id varchar(64),
    package_name varchar(255),
    ecosystem varchar(64),
    owner_group varchar(255),
    assigned_to varchar(255),
    incident_id varchar(64),
    due_at timestamptz,
    asset_name varchar(255),
    support_group varchar(255),
    patch_available boolean NOT NULL,
    suppressed_until timestamptz,
    risk_score double precision NOT NULL,
    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    first_observed_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_status_due
    ON finding_list_projection (status, due_at);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_assigned_status
    ON finding_list_projection (assigned_to, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_owner_status
    ON finding_list_projection (owner_group, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_incident_status
    ON finding_list_projection (incident_id, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_suppressed_status
    ON finding_list_projection (suppressed_until, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_updated_tiebreak
    ON finding_list_projection (updated_at, finding_id);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_severity_status
    ON finding_list_projection (severity, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_support_status
    ON finding_list_projection (support_group, status);

CREATE INDEX IF NOT EXISTS idx_finding_list_projection_patch_status
    ON finding_list_projection (patch_available, status);

CREATE TABLE IF NOT EXISTS finding_workspace_projection_status (
    projection_key varchar(64) PRIMARY KEY,
    last_computed_at timestamptz NOT NULL,
    finding_count bigint NOT NULL
);


-- source: V4__finding_projection_status_observability.sql
ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS source_finding_count bigint NOT NULL DEFAULT 0;

ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS last_rebuild_duration_ms bigint;


-- source: V5__widen_kev_required_action.sql
ALTER TABLE platform.vulnerabilities
    ALTER COLUMN kev_required_action TYPE varchar(2000);


-- source: V6__bom_ingestion_records.sql
-- BOM ingestion tracking: one record per BOM file ingested, any type
CREATE TABLE IF NOT EXISTS tenant_default.bom_ingestion_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES platform.tenants(id),
    sbom_upload_id  UUID,
    asset_id        UUID,
    bom_type        VARCHAR(20)  NOT NULL,
    format          VARCHAR(20),
    format_version  VARCHAR(10),
    serial_number   TEXT,
    supplier        VARCHAR(255),
    source_method   VARCHAR(20)  NOT NULL DEFAULT 'URL',
    source_url      TEXT,
    component_count INTEGER      NOT NULL DEFAULT 0,
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    superseded_by   UUID,
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ingested_by     TEXT
);

CREATE INDEX IF NOT EXISTS idx_bom_ir_tenant        ON tenant_default.bom_ingestion_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_bom_ir_asset         ON tenant_default.bom_ingestion_records (asset_id);
CREATE INDEX IF NOT EXISTS idx_bom_ir_status_type   ON tenant_default.bom_ingestion_records (tenant_id, bom_type, status);
CREATE INDEX IF NOT EXISTS idx_bom_ir_ingested_at   ON tenant_default.bom_ingestion_records (tenant_id, ingested_at DESC);


-- source: V7__bom_components.sql
-- Per-component rows enriched with BOM type metadata
CREATE TABLE IF NOT EXISTS tenant_default.bom_components (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bom_id         UUID NOT NULL,
    tenant_id      UUID NOT NULL REFERENCES platform.tenants(id),
    name           TEXT NOT NULL,
    version        TEXT,
    purl           TEXT,
    cpe            TEXT,
    license        TEXT,
    supplier       TEXT,
    component_type VARCHAR(40),
    category       VARCHAR(30) NOT NULL DEFAULT 'UNMATCHED',
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    hashes         JSONB,
    properties     JSONB
);

CREATE INDEX IF NOT EXISTS idx_bom_comp_bom_id   ON tenant_default.bom_components (bom_id);
CREATE INDEX IF NOT EXISTS idx_bom_comp_tenant   ON tenant_default.bom_components (tenant_id);
CREATE INDEX IF NOT EXISTS idx_bom_comp_active   ON tenant_default.bom_components (bom_id, is_active);
CREATE INDEX IF NOT EXISTS idx_bom_comp_purl     ON tenant_default.bom_components (purl) WHERE purl IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bom_comp_cpe      ON tenant_default.bom_components (cpe)  WHERE cpe  IS NOT NULL;


-- source: V8__inventory_component_group_license_scope.sql
-- Add group, license, and scope columns to inventory_components for SBOM enrichment
ALTER TABLE tenant_default.inventory_components
    ADD COLUMN IF NOT EXISTS package_group VARCHAR(255),
    ADD COLUMN IF NOT EXISTS license       TEXT,
    ADD COLUMN IF NOT EXISTS scope         VARCHAR(30);


-- source: V9__remediation_campaigns.sql
CREATE TABLE IF NOT EXISTS tenant_default.campaigns (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants (id),
    name varchar(255) NOT NULL,
    summary text,
    status varchar(32) NOT NULL,
    created_by varchar(255) NOT NULL,
    due_at timestamptz,
    started_at timestamptz,
    paused_at timestamptz,
    closed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_status_updated
    ON tenant_default.campaigns (tenant_id, status, updated_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_vulnerabilities (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    vulnerability_id uuid NOT NULL REFERENCES platform.vulnerabilities (id),
    external_id varchar(64) NOT NULL,
    title varchar(500),
    severity varchar(32),
    created_at timestamptz NOT NULL,
    CONSTRAINT uk_campaign_vulnerabilities_campaign_external UNIQUE (campaign_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_vulnerabilities_campaign
    ON tenant_default.campaign_vulnerabilities (campaign_id, external_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_notify_groups (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    group_name varchar(255) NOT NULL,
    role_label varchar(128),
    trigger_summary varchar(255),
    notifications_paused boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_notify_groups_campaign
    ON tenant_default.campaign_notify_groups (campaign_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_watchlist_entries (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    entry_type varchar(32) NOT NULL,
    label varchar(255) NOT NULL,
    email varchar(255),
    trigger_policy varchar(64),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_watchlist_entries_campaign
    ON tenant_default.campaign_watchlist_entries (campaign_id);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_notes (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    author varchar(255) NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_notes_campaign_created
    ON tenant_default.campaign_notes (campaign_id, created_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_activities (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    activity_type varchar(64) NOT NULL,
    actor varchar(255) NOT NULL,
    body text NOT NULL,
    metadata_json jsonb,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_activities_campaign_created
    ON tenant_default.campaign_activities (campaign_id, created_at desc);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_delivery_attempts (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    target_type varchar(32) NOT NULL,
    target_label varchar(255) NOT NULL,
    target_address varchar(255),
    subject varchar(500) NOT NULL,
    delivery_state varchar(32) NOT NULL,
    provider_message_id varchar(255),
    detail varchar(1000),
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_delivery_attempts_campaign_created
    ON tenant_default.campaign_delivery_attempts (campaign_id, created_at desc);


-- source: V10__campaign_exceptions.sql
ALTER TABLE tenant_default.campaign_watchlist_entries
    ADD COLUMN IF NOT EXISTS trigger_policy varchar(64);

CREATE TABLE IF NOT EXISTS tenant_default.campaign_exceptions (
    id uuid PRIMARY KEY,
    campaign_id uuid NOT NULL REFERENCES tenant_default.campaigns (id) ON DELETE CASCADE,
    finding_display_id varchar(64),
    asset_name varchar(255),
    package_name varchar(255),
    title varchar(255) NOT NULL,
    reason text NOT NULL,
    status varchar(32) NOT NULL,
    requested_by varchar(255) NOT NULL,
    requested_at timestamptz NOT NULL,
    decision_due_at timestamptz,
    decisioned_by varchar(255),
    decisioned_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_exceptions_campaign_requested
    ON tenant_default.campaign_exceptions (campaign_id, requested_at desc);


-- source: V11__campaign_group_delivery_and_updates.sql
ALTER TABLE tenant_default.campaign_notify_groups
    ADD COLUMN IF NOT EXISTS group_email varchar(255);


-- source: V12__bom_architecture_foundation.sql
ALTER TABLE tenant_default.bom_ingestion_records
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(40) NOT NULL DEFAULT 'URL',
    ADD COLUMN IF NOT EXISTS source_system VARCHAR(80),
    ADD COLUMN IF NOT EXISTS source_reference TEXT,
    ADD COLUMN IF NOT EXISTS source_endpoint TEXT,
    ADD COLUMN IF NOT EXISTS source_label TEXT,
    ADD COLUMN IF NOT EXISTS spec_family VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS document_format VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS document_name TEXT,
    ADD COLUMN IF NOT EXISTS content_type VARCHAR(120),
    ADD COLUMN IF NOT EXISTS content_length_bytes BIGINT,
    ADD COLUMN IF NOT EXISTS checksum_sha256 VARCHAR(128),
    ADD COLUMN IF NOT EXISTS previous_bom_id UUID;

UPDATE tenant_default.bom_ingestion_records
SET source_type = COALESCE(NULLIF(source_method, ''), 'URL')
WHERE source_type IS NULL OR source_type = '';

UPDATE tenant_default.bom_ingestion_records
SET source_reference = COALESCE(source_reference, source_url)
WHERE source_reference IS NULL;

UPDATE tenant_default.bom_ingestion_records
SET source_system = COALESCE(
    source_system,
    CASE
        WHEN source_method IN ('URL', 'UPLOAD') THEN 'manual'
        ELSE LOWER(source_method)
    END
)
WHERE source_system IS NULL;

UPDATE tenant_default.bom_ingestion_records
SET spec_family = CASE
    WHEN format = 'CYCLONEDX' THEN 'CYCLONEDX'
    WHEN format = 'SPDX' THEN 'SPDX'
    ELSE 'UNKNOWN'
END
WHERE spec_family IS NULL OR spec_family = 'UNKNOWN';

UPDATE tenant_default.bom_ingestion_records
SET document_name = COALESCE(document_name, source_reference)
WHERE document_name IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_schema = 'tenant_default'
          AND table_name = 'bom_ingestion_records'
          AND constraint_name = 'fk_bom_ir_previous_bom'
    ) THEN
        ALTER TABLE tenant_default.bom_ingestion_records
            ADD CONSTRAINT fk_bom_ir_previous_bom
            FOREIGN KEY (previous_bom_id)
            REFERENCES tenant_default.bom_ingestion_records(id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_bom_ir_source_type
    ON tenant_default.bom_ingestion_records (tenant_id, source_type, status);
CREATE INDEX IF NOT EXISTS idx_bom_ir_source_system
    ON tenant_default.bom_ingestion_records (tenant_id, source_system);
CREATE INDEX IF NOT EXISTS idx_bom_ir_spec_family
    ON tenant_default.bom_ingestion_records (tenant_id, spec_family, format_version);

ALTER TABLE tenant_default.bom_components
    ADD COLUMN IF NOT EXISTS bom_ref TEXT,
    ADD COLUMN IF NOT EXISTS group_name TEXT,
    ADD COLUMN IF NOT EXISTS scope TEXT,
    ADD COLUMN IF NOT EXISTS swid TEXT,
    ADD COLUMN IF NOT EXISTS external_references JSONB,
    ADD COLUMN IF NOT EXISTS workflow_status VARCHAR(40) NOT NULL DEFAULT 'DISCOVERED';

UPDATE tenant_default.bom_components
SET group_name = supplier
WHERE group_name IS NULL AND supplier IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_evidence (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    bom_id           UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    evidence_type    VARCHAR(40) NOT NULL,
    evidence_key     TEXT,
    evidence_value   TEXT,
    source_system    VARCHAR(80),
    source_reference TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bom_evidence_component
    ON tenant_default.bom_component_evidence (bom_component_id, evidence_type);
CREATE INDEX IF NOT EXISTS idx_bom_evidence_bom
    ON tenant_default.bom_component_evidence (bom_id);

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_vulnerability_links (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id          UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    bom_id                    UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    vulnerability_key         VARCHAR(128) NOT NULL,
    vulnerability_source      VARCHAR(40) NOT NULL DEFAULT 'NVD',
    relation_type             VARCHAR(40) NOT NULL DEFAULT 'CVE',
    match_source              VARCHAR(80),
    match_confidence          NUMERIC(5,2),
    direct_match              BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_evidence_json JSONB,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_component
    ON tenant_default.bom_component_vulnerability_links (bom_component_id, vulnerability_key);
CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_bom
    ON tenant_default.bom_component_vulnerability_links (bom_id);
CREATE INDEX IF NOT EXISTS idx_bom_vuln_link_source
    ON tenant_default.bom_component_vulnerability_links (tenant_id, vulnerability_source, relation_type);

CREATE TABLE IF NOT EXISTS tenant_default.bom_component_workflows (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    bom_component_id      UUID NOT NULL REFERENCES tenant_default.bom_components(id) ON DELETE CASCADE,
    vulnerability_link_id UUID REFERENCES tenant_default.bom_component_vulnerability_links(id) ON DELETE CASCADE,
    workflow_type         VARCHAR(40) NOT NULL DEFAULT 'INVESTIGATION',
    workflow_status       VARCHAR(40) NOT NULL DEFAULT 'DISCOVERED',
    workflow_reason       TEXT,
    investigation_key     VARCHAR(128),
    finding_id            UUID,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at             TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_bom_workflow_component
    ON tenant_default.bom_component_workflows (bom_component_id, workflow_status);
CREATE INDEX IF NOT EXISTS idx_bom_workflow_link
    ON tenant_default.bom_component_workflows (vulnerability_link_id);


-- source: V13__restore_finding_queue_tables.sql
CREATE TABLE IF NOT EXISTS platform.personal_finding_queues (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    queue_key varchar(120) NOT NULL,
    title varchar(160) NOT NULL,
    description varchar(500),
    filter_json text NOT NULL,
    display_order integer NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_personal_finding_queues_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_personal_finding_queues_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_personal_finding_queues_owner_key UNIQUE (tenant_id, owner_user_id, queue_key),
    CONSTRAINT uk_personal_finding_queues_owner_title UNIQUE (tenant_id, owner_user_id, title)
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_personal_finding_queues_owner_default
    ON platform.personal_finding_queues (tenant_id, owner_user_id)
    WHERE is_default = true;

CREATE INDEX IF NOT EXISTS idx_personal_finding_queues_owner_order
    ON platform.personal_finding_queues (tenant_id, owner_user_id, display_order, created_at);

CREATE TABLE IF NOT EXISTS platform.finding_queue_preferences (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    default_queue_ref varchar(160) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_finding_queue_preferences_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_finding_queue_preferences_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_finding_queue_preferences_owner UNIQUE (tenant_id, owner_user_id)
);

COMMENT ON TABLE platform.personal_finding_queues IS 'Personal finding queue definitions per tenant user';
COMMENT ON TABLE platform.finding_queue_preferences IS 'Per-user default finding queue selection';


-- source: V14__github_sbom_source_token.sql
ALTER TABLE tenant_default.github_sbom_sources ADD COLUMN IF NOT EXISTS github_token TEXT;


-- source: V15__tenant_user_invites.sql
CREATE TABLE IF NOT EXISTS platform.tenant_user_invites (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    invited_by uuid,
    email varchar(320) NOT NULL,
    display_name varchar(255),
    external_subject varchar(320) NOT NULL,
    role varchar(64) NOT NULL,
    status varchar(32) NOT NULL,
    token varchar(96) NOT NULL,
    provider_message_id varchar(255),
    delivery_detail varchar(500),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    last_sent_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_tenant_user_invites_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_user_invites_invited_by FOREIGN KEY (invited_by) REFERENCES platform.app_users (id),
    CONSTRAINT uk_tenant_user_invites_token UNIQUE (token)
);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_tenant_created
    ON platform.tenant_user_invites (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_tenant_status
    ON platform.tenant_user_invites (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_subject_status
    ON platform.tenant_user_invites (external_subject, status);


-- source: V16__ingestion_jobs.sql
CREATE TABLE IF NOT EXISTS tenant_default.ingestion_jobs (
    id uuid PRIMARY KEY,
    job_type varchar(80) NOT NULL,
    source_type varchar(80) NOT NULL,
    asset_identifier varchar(500) NOT NULL,
    status varchar(32) NOT NULL,
    requested_by varchar(255),
    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    dedupe_key varchar(700) NOT NULL,
    payload_json text,
    result_json text,
    failure_code varchar(120),
    failure_message text,
    visible_at timestamptz NOT NULL DEFAULT now(),
    sbom_upload_id uuid,
    tenant_id uuid NOT NULL,
    CONSTRAINT ingestion_jobs_status_check CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    CONSTRAINT fk_ingestion_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_ingestion_jobs_sbom_upload FOREIGN KEY (sbom_upload_id) REFERENCES tenant_default.sbom_uploads (id)
);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_status_visible
    ON tenant_default.ingestion_jobs (status, visible_at, id);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_requested_desc
    ON tenant_default.ingestion_jobs (requested_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_asset_status
    ON tenant_default.ingestion_jobs (asset_identifier, status);

CREATE UNIQUE INDEX IF NOT EXISTS uk_ingestion_jobs_dedupe_active
    ON tenant_default.ingestion_jobs (dedupe_key)
    WHERE status IN ('QUEUED', 'RUNNING');


-- source: V17__tenant_ingestion_admission_quotas.sql
ALTER TABLE platform.tenants
    ADD COLUMN IF NOT EXISTS sbom_rate_limit_window_seconds INTEGER,
    ADD COLUMN IF NOT EXISTS max_sbom_jobs_per_rate_limit_window INTEGER,
    ADD COLUMN IF NOT EXISTS max_active_sbom_jobs INTEGER;


-- source: V18__tenant_plan_defaults.sql
CREATE TABLE IF NOT EXISTS platform.plan_definitions (
    code varchar(64) PRIMARY KEY,
    display_name varchar(120) NOT NULL,
    status varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

UPDATE platform.tenants
SET plan_code = CASE
    WHEN plan_code IS NULL OR trim(plan_code) = '' THEN 'ENTERPRISE'
    WHEN upper(trim(plan_code)) = 'PILOT' THEN 'ENTERPRISE'
    ELSE upper(trim(plan_code))
END
WHERE plan_code IS NULL
   OR trim(plan_code) = ''
   OR upper(trim(plan_code)) <> plan_code
   OR upper(trim(plan_code)) = 'PILOT';

INSERT INTO platform.plan_definitions (code, display_name, status, description, created_at, updated_at)
VALUES
    ('PRO', 'Pro', 'ACTIVE', 'Legacy commercial plan label retained for compatibility', now(), now()),
    ('ENTERPRISE', 'Enterprise', 'ACTIVE', 'Default workspace plan label retained for compatibility', now(), now()),
    ('DEMO', 'Demo', 'ACTIVE', 'Demo tenant plan label retained for compatibility', now(), now()),
    ('PILOT', 'Pilot', 'ACTIVE', 'Legacy pilot plan retained for compatibility', now(), now())
ON CONFLICT (code) DO NOTHING;


-- source: V19__backfill_github_sbom_source_token_all_tenants.sql
DO $$
DECLARE
    schema_record record;
BEGIN
    FOR schema_record IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'github_sbom_sources'
          AND table_schema NOT IN ('information_schema', 'pg_catalog')
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.github_sbom_sources ADD COLUMN IF NOT EXISTS github_token TEXT',
                schema_record.table_schema
        );
    END LOOP;
END
$$;


-- source: V20__cbom_crypto_asset_layer.sql
CREATE TABLE IF NOT EXISTS tenant_default.cbom_components (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    asset_id              UUID REFERENCES tenant_default.assets(id),
    source_bom_id         UUID NOT NULL REFERENCES tenant_default.bom_ingestion_records(id) ON DELETE CASCADE,
    bom_ref               TEXT,
    component_fingerprint TEXT NOT NULL,
    name                  TEXT NOT NULL,
    description           TEXT,
    asset_type            VARCHAR(60) NOT NULL,
    component_type        TEXT,
    primitive             TEXT,
    parameter_set_identifier TEXT,
    key_size              INTEGER,
    curve                 TEXT,
    padding               TEXT,
    protocol_version      TEXT,
    state                 TEXT,
    format                TEXT,
    storage_location      TEXT,
    transmission          TEXT,
    sensitivity           TEXT,
    used_in               TEXT,
    not_before            DATE,
    not_after             DATE,
    issuer                TEXT,
    subject               TEXT,
    serial_number         TEXT,
    signature_algorithm   TEXT,
    key_usage             TEXT,
    risk_score            NUMERIC(4,2),
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_bom_id, component_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_cbom_components_tenant_asset
    ON tenant_default.cbom_components (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_cbom_components_source_bom
    ON tenant_default.cbom_components (source_bom_id);
CREATE INDEX IF NOT EXISTS idx_cbom_components_bom_ref
    ON tenant_default.cbom_components (tenant_id, asset_id, bom_ref)
    WHERE bom_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cbom_components_asset_type
    ON tenant_default.cbom_components (tenant_id, asset_type);

CREATE TABLE IF NOT EXISTS tenant_default.cbom_risk_findings (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    cbom_component_id     UUID NOT NULL REFERENCES tenant_default.cbom_components(id) ON DELETE CASCADE,
    rule_id               VARCHAR(100) NOT NULL,
    rule_version          VARCHAR(20) NOT NULL DEFAULT '1',
    finding_fingerprint   TEXT NOT NULL,
    risk_class            VARCHAR(80) NOT NULL,
    severity              VARCHAR(20) NOT NULL,
    title                 TEXT NOT NULL,
    detail                TEXT,
    evidence              JSONB,
    recommendation        TEXT,
    status                VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cbom_component_id, finding_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_cbom_risk_findings_component
    ON tenant_default.cbom_risk_findings (cbom_component_id);
CREATE INDEX IF NOT EXISTS idx_cbom_risk_findings_tenant_status
    ON tenant_default.cbom_risk_findings (tenant_id, status, severity);

CREATE TABLE IF NOT EXISTS tenant_default.cbom_posture_summary (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES platform.tenants(id),
    asset_id              UUID NOT NULL REFERENCES tenant_default.assets(id),
    last_source_bom_id    UUID REFERENCES tenant_default.bom_ingestion_records(id),
    total_components      INTEGER NOT NULL DEFAULT 0,
    critical_findings     INTEGER NOT NULL DEFAULT 0,
    high_findings         INTEGER NOT NULL DEFAULT 0,
    medium_findings       INTEGER NOT NULL DEFAULT 0,
    low_findings          INTEGER NOT NULL DEFAULT 0,
    info_findings         INTEGER NOT NULL DEFAULT 0,
    accepted_findings     INTEGER NOT NULL DEFAULT 0,
    quantum_vulnerable    INTEGER NOT NULL DEFAULT 0,
    weak_algorithms       INTEGER NOT NULL DEFAULT 0,
    expiring_certs        INTEGER NOT NULL DEFAULT 0,
    posture_score         NUMERIC(4,2),
    last_evaluated_at     TIMESTAMPTZ,
    UNIQUE (tenant_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cbom_posture_summary_tenant
    ON tenant_default.cbom_posture_summary (tenant_id);


-- source: V21__finding_auto_close_lifecycle.sql
ALTER TABLE tenant_default.findings
    ADD COLUMN IF NOT EXISTS last_observed_run_id uuid,
    ADD COLUMN IF NOT EXISTS consecutive_misses integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_close_eligible_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_by varchar(255),
    ADD COLUMN IF NOT EXISTS closed_reason varchar(80),
    ADD COLUMN IF NOT EXISTS closed_rule_id uuid;

CREATE INDEX IF NOT EXISTS idx_findings_auto_close_eligible
    ON tenant_default.findings (tenant_id, status, auto_close_eligible_at);

ALTER TABLE tenant_default.risk_policies
    ADD COLUMN IF NOT EXISTS auto_close_required_consecutive_misses integer NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS auto_close_not_observed_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_component_removed_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_asset_retired_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_close_source_disabled_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS auto_close_duplicate_enabled boolean NOT NULL DEFAULT true;


-- source: V22__auto_close_run_schedule.sql
ALTER TABLE tenant_default.risk_policies
    ADD COLUMN IF NOT EXISTS auto_close_run_interval_days integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS auto_close_last_run_at timestamptz;


-- source: V23__default_risk_policy_presets.sql
-- Backfill tenant risk policies with the product default findings-score preset.
-- Fresh tenants already get the preset from the entity/service defaults; this
-- migration updates existing rows that were still using an empty config.

DO $$
DECLARE
    schema_record record;
    preset jsonb := $json$[
      {
        "table": "VULNERABILITY",
        "column": "cvssScore",
        "values": [
          { "operator": ">=", "value": "9", "weight": 0.2 },
          { "operator": "<=", "value": "8", "weight": 0.1 }
        ]
      },
      {
        "table": "VULNERABILITY",
        "column": "exploitExists",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      },
      {
        "table": "ASSET",
        "column": "businessCriticality",
        "values": [
          { "operator": "=", "value": "high", "weight": 0.2 }
        ]
      },
      {
        "table": "ASSET",
        "column": "internetFacing",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      },
      {
        "table": "VULNERABILITY",
        "column": "isInKev",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      }
    ]$json$::jsonb;
BEGIN
    FOR schema_record IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'risk_policies'
          AND table_schema NOT IN ('information_schema', 'pg_catalog')
    LOOP
        EXECUTE format(
                'UPDATE %I.risk_policies
                 SET findings_score_config = $1
                 WHERE findings_score_config IS NULL OR findings_score_config = ''[]''::jsonb',
                schema_record.table_schema
        )
        USING preset;
    END LOOP;
END
$$;


-- source: V24__enable_investigation_agent_all_plans.sql
UPDATE platform.plan_entitlements
SET enabled = true,
    updated_at = now()
WHERE entitlement_key = 'ai.investigation_agent';


-- source: V25__widen_tenant_purge_error.sql
ALTER TABLE platform.tenants
    ALTER COLUMN purge_error TYPE varchar(2000);


-- source: V26__repair_tenant_fk_references.sql
-- Repair foreign-key constraints in non-default tenant schemas that were copied verbatim
-- from tenant_default by an earlier provisionTenantSchema implementation. Those FKs
-- reference tenant_default.<table> instead of <own_schema>.<table>, so any insert into the
-- affected tenant's table that depended on within-tenant referential integrity (e.g.
-- cis.asset_id -> assets.id) failed with a foreign-key violation.
--
-- This migration finds every such cross-schema FK pointing at tenant_default from a
-- tenant_<name> schema, drops it, and recreates it pointing at the FK's own schema.
-- Only FKs whose referenced table also exists in the local schema are rewritten so we
-- never silently drop a constraint we cannot replace.

DO $$
DECLARE
    rec RECORD;
    new_def TEXT;
BEGIN
    FOR rec IN
        SELECT
            n.nspname    AS schema_name,
            cl.relname   AS table_name,
            con.conname  AS constraint_name,
            pg_get_constraintdef(con.oid) AS definition,
            confcl.relname AS referenced_table
        FROM pg_constraint con
        JOIN pg_class cl     ON cl.oid = con.conrelid
        JOIN pg_namespace n  ON n.oid = cl.relnamespace
        JOIN pg_class confcl ON confcl.oid = con.confrelid
        JOIN pg_namespace confn ON confn.oid = confcl.relnamespace
        WHERE con.contype = 'f'
          AND n.nspname LIKE 'tenant\_%' ESCAPE '\'
          AND n.nspname <> 'tenant_default'
          AND confn.nspname = 'tenant_default'
          AND EXISTS (
              SELECT 1 FROM pg_tables t
              WHERE t.schemaname = n.nspname
                AND t.tablename  = confcl.relname
          )
    LOOP
        new_def := replace(
            rec.definition,
            'REFERENCES tenant_default.',
            'REFERENCES ' || quote_ident(rec.schema_name) || '.'
        );
        EXECUTE format(
            'ALTER TABLE %I.%I DROP CONSTRAINT %I',
            rec.schema_name, rec.table_name, rec.constraint_name
        );
        EXECUTE format(
            'ALTER TABLE %I.%I ADD CONSTRAINT %I %s',
            rec.schema_name, rec.table_name, rec.constraint_name, new_def
        );
    END LOOP;
END
$$;


-- source: V27__restore_entitlement_seed_data.sql
-- Restore the entitlement seed data that was lost when the original entitlements migration was
-- dropped from the migration set. The platform.entitlement_definitions and platform.plan_entitlements
-- tables are created in V1; this migration populates them.
--
-- It runs after V18 (which seeds platform.plan_definitions), so the plan_code foreign keys resolve,
-- and is fully idempotent (ON CONFLICT DO NOTHING) so databases that already hold this data — every
-- existing deployment — are unaffected. On a fresh database this makes the AI entitlements available
-- for all plans, matching production, so V24__enable_investigation_agent_all_plans.sql has rows to act on.

INSERT INTO platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at)
VALUES
    ('ai.investigation_summary',  'AI', 'BOOLEAN', 'Generate AI investigation summaries', now(), now()),
    ('ai.solution_generation',    'AI', 'BOOLEAN', 'Generate AI remediation solutions', now(), now()),
    ('ai.required_actions',       'AI', 'BOOLEAN', 'Generate AI required actions', now(), now()),
    ('ai.fix_generation',         'AI', 'BOOLEAN', 'Generate AI fix records', now(), now()),
    ('ai.upgrade_recommendation', 'AI', 'BOOLEAN', 'Generate AI upgrade recommendations', now(), now()),
    ('ai.investigation_agent',    'AI', 'BOOLEAN', 'Run AI investigation agent workflows', now(), now())
ON CONFLICT (key) DO NOTHING;

INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, ed.key, true, NULL, now(), now()
FROM platform.plan_definitions pd
CROSS JOIN platform.entitlement_definitions ed
WHERE pd.code IN ('PRO', 'ENTERPRISE', 'DEMO', 'PILOT')
  AND ed.category = 'AI'
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;


-- source: V28__tenant_schema_reconciliation.sql
DO $$
DECLARE
    target_schema record;
    source_table record;
    source_column record;
BEGIN
    FOR target_schema IN
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name LIKE 'tenant\_%' ESCAPE '\'
          AND schema_name <> 'tenant_default'
    LOOP
        FOR source_table IN
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'tenant_default'
              AND tablename NOT IN ('flyway_schema_history', 'sync_runs')
            ORDER BY tablename
        LOOP
            EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I.%I (LIKE tenant_default.%I INCLUDING CONSTRAINTS INCLUDING GENERATED INCLUDING IDENTITY INCLUDING INDEXES INCLUDING STORAGE INCLUDING COMMENTS)',
                    target_schema.schema_name,
                    source_table.tablename,
                    source_table.tablename
            );
        END LOOP;

        FOR source_column IN
            SELECT c.table_name,
                   c.column_name,
                   c.data_type,
                   c.udt_name,
                   c.character_maximum_length,
                   c.numeric_precision,
                   c.numeric_scale,
                   c.datetime_precision,
                   c.column_default
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON t.table_schema = c.table_schema
             AND t.table_name = c.table_name
            WHERE c.table_schema = 'tenant_default'
              AND t.table_type = 'BASE TABLE'
              AND c.table_name NOT IN ('flyway_schema_history', 'sync_runs')
              AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns existing
                    WHERE existing.table_schema = target_schema.schema_name
                      AND existing.table_name = c.table_name
                      AND existing.column_name = c.column_name
              )
            ORDER BY c.table_name, c.ordinal_position
        LOOP
            EXECUTE format(
                    'ALTER TABLE %I.%I ADD COLUMN IF NOT EXISTS %I %s%s',
                    target_schema.schema_name,
                    source_column.table_name,
                    source_column.column_name,
                    CASE
                        WHEN source_column.data_type = 'USER-DEFINED' THEN source_column.udt_name
                        WHEN source_column.data_type IN ('character varying', 'character')
                            THEN source_column.data_type || COALESCE('(' || source_column.character_maximum_length || ')', '')
                        WHEN source_column.data_type = 'numeric' AND source_column.numeric_precision IS NOT NULL
                            THEN source_column.data_type || '(' || source_column.numeric_precision || COALESCE(',' || source_column.numeric_scale, '') || ')'
                        WHEN source_column.data_type LIKE 'timestamp%'
                            THEN source_column.data_type
                        ELSE source_column.data_type
                    END,
                    CASE
                        WHEN source_column.column_default IS NULL THEN ''
                        ELSE ' DEFAULT ' || replace(source_column.column_default, 'tenant_default.', format('%I.', target_schema.schema_name))
                    END
            );
        END LOOP;
    END LOOP;
END
$$;


-- source: V29__tenant_rls_rollout_gate.sql
-- RLS rollout gate.
--
-- Do not enable tenant RLS in the guardrail/background-fix rollout. RLS policy
-- creation, data validation, hot-path performance checks, and FORCE ROW LEVEL
-- SECURITY belong in the dedicated Phase 4 rollout migration once production
-- and preproduction runtime roles have been verified as non-superuser,
-- non-BYPASSRLS, and non-owner for protected tables.
SELECT 1;


-- source: V30__move_sync_runs_to_platform.sql
CREATE TABLE IF NOT EXISTS platform.sync_runs (
    id uuid PRIMARY KEY,
    completed_at timestamptz,
    error_message varchar(2000),
    metadata_json text,
    records_failed integer NOT NULL DEFAULT 0,
    records_fetched integer NOT NULL DEFAULT 0,
    records_inserted integer NOT NULL DEFAULT 0,
    records_updated integer NOT NULL DEFAULT 0,
    run_scope varchar(64) NOT NULL DEFAULT 'PLATFORM_VULNERABILITY',
    started_at timestamptz NOT NULL,
    status varchar(255) NOT NULL,
    sync_type varchar(255) NOT NULL,
    tenant_id uuid,
    CONSTRAINT fk_sync_runs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id)
);

DO $$
DECLARE
    source_schema record;
BEGIN
    FOR source_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'sync_runs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format($sql$
            INSERT INTO platform.sync_runs (
                id,
                completed_at,
                error_message,
                metadata_json,
                records_failed,
                records_fetched,
                records_inserted,
                records_updated,
                run_scope,
                started_at,
                status,
                sync_type,
                tenant_id
            )
            SELECT
                id,
                completed_at,
                error_message,
                metadata_json,
                COALESCE(records_failed, 0),
                records_fetched,
                records_inserted,
                records_updated,
                run_scope,
                started_at,
                status,
                sync_type,
                tenant_id
            FROM %I.sync_runs
            ON CONFLICT (id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                error_message = EXCLUDED.error_message,
                metadata_json = EXCLUDED.metadata_json,
                records_failed = EXCLUDED.records_failed,
                records_fetched = EXCLUDED.records_fetched,
                records_inserted = EXCLUDED.records_inserted,
                records_updated = EXCLUDED.records_updated,
                run_scope = EXCLUDED.run_scope,
                started_at = EXCLUDED.started_at,
                status = EXCLUDED.status,
                sync_type = EXCLUDED.sync_type,
                tenant_id = EXCLUDED.tenant_id
            $sql$, source_schema.table_schema);
    END LOOP;

    FOR source_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'sync_runs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I.sync_runs CASCADE', source_schema.table_schema);
    END LOOP;
END
$$;

CREATE INDEX IF NOT EXISTS idx_sync_runs_run_scope_started
    ON platform.sync_runs (run_scope, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant_started
    ON platform.sync_runs (tenant_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_runs_sync_type_status
    ON platform.sync_runs (lower(sync_type), lower(status), started_at DESC);


-- source: V31__widen_servicenow_cmdb_text_columns.sql
-- Widen servicenow_cmdb_configs columns that were too narrow (varchar 255)
-- to match the entity declarations (install_fields/discovery_fields/queries -> 4000,
-- last_test_message -> 2000) across every tenant schema.
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'servicenow_cmdb_configs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.servicenow_cmdb_configs
                    ALTER COLUMN install_fields TYPE varchar(4000),
                    ALTER COLUMN install_query TYPE varchar(4000),
                    ALTER COLUMN discovery_fields TYPE varchar(4000),
                    ALTER COLUMN discovery_query TYPE varchar(4000),
                    ALTER COLUMN last_test_message TYPE varchar(2000)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V32__projection_and_fix_record_perf_indexes.sql
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'finding_list_projection'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_finding_list_projection_rank_cursor
                    ON %I.finding_list_projection (
                        risk_score DESC,
                        coalesce(due_at, %L::timestamptz) ASC,
                        updated_at DESC,
                        finding_id ASC
                    )',
                target_schema.table_schema,
                '9999-12-31T00:00:00Z'
        );
    END LOOP;

    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'fix_records'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_fix_records_patchable_upper_cve
                    ON %I.fix_records (upper(cve_id))
                    WHERE upper(fix_type) <> %L',
                target_schema.table_schema,
                'NO_FIX'
        );
    END LOOP;
END
$$;


-- source: V33__org_cve_targeted_recompute_indexes.sql
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name IN ('findings', 'org_cve_records')
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_findings_tenant_status_component
                    ON %I.findings (tenant_id, status, component_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_created_at
                    ON %I.org_cve_records (tenant_id, created_at DESC)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_upper_severity
                    ON %I.org_cve_records (tenant_id, upper(coalesce(severity, %L)))',
                target_schema.table_schema,
                'UNKNOWN'
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_org_cve_record_tenant_exposure_browse
                    ON %I.org_cve_records (
                        tenant_id,
                        applicability_state,
                        matched_asset_count,
                        impacted,
                        in_kev,
                        epss_score DESC,
                        cvss_score DESC,
                        external_id
                    )',
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V34__org_cve_software_filter_indexes.sql
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name IN ('inventory_components', 'component_vulnerability_states')
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_inventory_tenant_software_identity
                    ON %I.inventory_components (tenant_id, software_identity_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_tenant_vulnerability_component
                    ON %I.component_vulnerability_states (tenant_id, vulnerability_id, component_id)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V35__vulnerability_source_lookup_indexes.sql
-- migration-guard: flyway-per-schema
CREATE INDEX IF NOT EXISTS idx_vuln_intel_obs_source_vuln
    ON platform.vulnerability_intel_observations (source_system, vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_vintel_summary_source_source_vuln
    ON platform.vulnerability_intel_summary_sources (source_system, vulnerability_id);


-- source: V36__demo_request_bootstrap_status.sql
DO $$
DECLARE
    target_schema text;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'demo_requests'
          AND (table_schema = 'tenant_default' OR table_schema LIKE 'tenant\_%' ESCAPE '\')
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.demo_requests ADD COLUMN IF NOT EXISTS bootstrap_status varchar(64)',
                target_schema);
    END LOOP;
END $$;


-- source: V37__repair_demo_request_bootstrap_status.sql
DO $$
DECLARE
    target_schema text;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'demo_requests'
          AND (
              table_schema = 'public'
              OR table_schema = 'tenant_default'
              OR table_schema LIKE 'tenant\_%' ESCAPE '\'
          )
    LOOP
        EXECUTE format(
                'ALTER TABLE %I.demo_requests ADD COLUMN IF NOT EXISTS bootstrap_status varchar(64)',
                target_schema);
    END LOOP;
END $$;


-- source: V38__tenant_entitlement_overrides.sql
-- migration-guard: flyway-per-schema
-- platform.tenant_entitlement_overrides is queried by TenantEntitlementService (loadTenantOverrides,
-- listOverrides, upsertOverride, deleteOverride, existingOverrideId) but was never created by a
-- migration, causing a BadSqlGrammarException (surfaced to callers as a generic 500) on any endpoint
-- that resolves tenant entitlements, e.g. POST /api/upgrade-recommendation.
CREATE TABLE IF NOT EXISTS platform.tenant_entitlement_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    entitlement_key varchar(128) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    reason varchar(500),
    expires_at timestamptz,
    created_by uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uk_tenant_entitlement_overrides_tenant_key UNIQUE (tenant_id, entitlement_key),
    CONSTRAINT fk_tenant_entitlement_overrides_tenant
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_entitlement_overrides_entitlement_key
        FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions (key)
);

CREATE INDEX IF NOT EXISTS idx_tenant_entitlement_overrides_tenant ON platform.tenant_entitlement_overrides (tenant_id);


-- source: V39__software_identity_metadata.sql
-- tenant_<schema>.software_identity_metadata is read/written by SoftwareIdentityMetadataService
-- (getMetadata / saveMetadata, incl. an INSERT ... ON CONFLICT (tenant_id, software_identity_id) upsert)
-- but was never created by a migration, causing a BadSqlGrammarException (surfaced to callers as a
-- generic "[INTERNAL_ERROR] Internal server error") on PUT/GET /api/inventory/software-identities/{id}/metadata.
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'assets'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                $ddl$CREATE TABLE IF NOT EXISTS %I.software_identity_metadata (
                    tenant_id uuid NOT NULL,
                    software_identity_id uuid NOT NULL,
                    owner text,
                    licensed text NOT NULL DEFAULT 'Unknown',
                    license_type text,
                    support_group text,
                    recommendation text,
                    recommendation_updated_at timestamptz,
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, software_identity_id),
                    CONSTRAINT fk_software_identity_metadata_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT fk_software_identity_metadata_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities (id)
                )$ddl$,
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V40__azure_discovery_configs.sql
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'assets'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.azure_discovery_configs (
                    id UUID PRIMARY KEY,
                    tenant_id UUID NOT NULL,
                    source_system VARCHAR(80) NOT NULL DEFAULT ''azure'',
                    auth_type VARCHAR(32) NOT NULL DEFAULT ''CLIENT_SECRET'',
                    azure_tenant_id VARCHAR(128),
                    client_id VARCHAR(255),
                    client_secret TEXT,
                    subscription_ids_json TEXT NOT NULL DEFAULT ''[]'',
                    regions_json TEXT NOT NULL DEFAULT ''["eastus2"]'',
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    auto_sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    interval_minutes INTEGER NOT NULL DEFAULT 1440,
                    last_test_status VARCHAR(64),
                    last_test_message VARCHAR(2000),
                    last_tested_at TIMESTAMPTZ,
                    last_sync_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    CONSTRAINT fk_azure_discovery_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT uk_azure_discovery_configs_tenant_source UNIQUE (tenant_id, source_system),
                    CONSTRAINT azure_discovery_configs_auth_type_check CHECK (auth_type IN (''CLIENT_SECRET'', ''MANAGED_IDENTITY''))
                )',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_configs_enabled
                    ON %I.azure_discovery_configs (enabled, auto_sync_enabled)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_configs_tenant
                    ON %I.azure_discovery_configs (tenant_id)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V41__azure_discovery_targets.sql
DO $$
DECLARE
    target_schema record;
BEGIN
    FOR target_schema IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'azure_discovery_configs'
          AND table_schema LIKE 'tenant\_%' ESCAPE '\'
        GROUP BY table_schema
        ORDER BY table_schema
    LOOP
        EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.azure_discovery_targets (
                    id UUID PRIMARY KEY,
                    tenant_id UUID NOT NULL,
                    config_id UUID NOT NULL,
                    subscription_id VARCHAR(64),
                    subscription_name VARCHAR(255),
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    regions_json TEXT NOT NULL DEFAULT ''["eastus2"]'',
                    last_test_status VARCHAR(64),
                    last_test_message VARCHAR(2000),
                    last_tested_at TIMESTAMPTZ,
                    last_sync_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    CONSTRAINT fk_azure_discovery_targets_config FOREIGN KEY (config_id) REFERENCES %I.azure_discovery_configs (id),
                    CONSTRAINT fk_azure_discovery_targets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
                    CONSTRAINT uk_azure_discovery_targets_config_subscription UNIQUE (config_id, subscription_id)
                )',
                target_schema.table_schema,
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_targets_config
                    ON %I.azure_discovery_targets (config_id)',
                target_schema.table_schema
        );

        EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_azure_discovery_targets_tenant_enabled
                    ON %I.azure_discovery_targets (tenant_id, enabled)',
                target_schema.table_schema
        );
    END LOOP;
END
$$;


-- source: V42__tenant_schema_control_plane.sql
CREATE TABLE IF NOT EXISTS platform.tenant_schema_versions (
    tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id) ON DELETE CASCADE,
    schema_name varchar(120) NOT NULL UNIQUE,
    current_version integer NOT NULL DEFAULT 0,
    target_version integer NOT NULL DEFAULT 42,
    status varchar(24) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'MIGRATING', 'CURRENT', 'FAILED', 'DRIFTED', 'PROVISIONING_FAILED')),
    structural_checksum varchar(64),
    migration_started_at timestamptz,
    migration_completed_at timestamptz,
    last_successful_version integer NOT NULL DEFAULT 0,
    failure_code varchar(80),
    failure_message varchar(1000),
    updated_at timestamptz NOT NULL DEFAULT now(),
    migration_run_id uuid
);

CREATE INDEX IF NOT EXISTS idx_tenant_schema_versions_status
    ON platform.tenant_schema_versions(status, current_version);

COMMENT ON TABLE platform.tenant_schema_versions IS
    'Operational projection of per-schema tenant_schema_history. Flyway history remains authoritative.';


-- source: V43__advance_tenant_schema_target.sql
ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 43;

UPDATE platform.tenant_schema_versions
SET target_version = 43,
    updated_at = now()
WHERE target_version < 43;


-- source: V44__advance_projection_schema_target.sql
ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 44;

UPDATE platform.tenant_schema_versions
SET target_version = 44,
    status = CASE WHEN current_version < 44 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 44;


-- source: V45__tenant_access_membership_provenance.sql
ALTER TABLE platform.tenant_memberships
    ADD COLUMN IF NOT EXISTS provenance varchar(32) NOT NULL DEFAULT 'MANUAL';

UPDATE platform.tenant_memberships
SET provenance = 'TENANT_INVITE'
WHERE invited_by IS NOT NULL
  AND provenance = 'MANUAL';

CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_memberships_user_tenant
    ON platform.tenant_memberships (user_id, tenant_id);

ALTER TABLE platform.tenant_support_grants
    ALTER COLUMN expires_at DROP NOT NULL;


-- source: V46__demo_request_active_email_uniqueness.sql
WITH ranked_active_requests AS (
    SELECT id,
           row_number() OVER (PARTITION BY lower(email) ORDER BY requested_at DESC, id DESC) AS request_rank
    FROM tenant_default.demo_requests
    WHERE status IN ('PENDING', 'SENT', 'ERROR')
)
UPDATE tenant_default.demo_requests request
SET status = 'SUPERSEDED',
    rejection_reason = coalesce(request.rejection_reason, 'Superseded by a newer active request')
FROM ranked_active_requests ranked
WHERE request.id = ranked.id
  AND ranked.request_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uk_demo_requests_active_email
    ON tenant_default.demo_requests (lower(email))
    WHERE status IN ('PENDING', 'SENT', 'ERROR');


-- source: V47__ai_security_entitlement_compatibility.sql
-- Phase 0 (AI Security) — entitlement resolution compatibility.
--
-- Correcting entitlement resolution precedence (active tenant override -> plan value ->
-- disabled default) means platform.plan_entitlements rows now actually drive runtime behavior,
-- where previously the resolver returned enabled=true unconditionally. The six existing ai.*
-- capabilities are already seeded enabled for PRO/ENTERPRISE/DEMO/PILOT by V27; this migration
-- re-asserts that seed idempotently so the compatibility guarantee lives inside the Phase 0
-- change set itself and does not depend on V27 having succeeded. ON CONFLICT DO NOTHING never
-- overrides an operator's deliberate value — any divergence surfaces through SHADOW-mode
-- mismatch telemetry for human review before ENFORCE cutover.
--
-- It also introduces the single AI Security pilot entitlement, ai.security, seeded DISABLED for
-- every plan. Per-tenant canary enablement is done through platform.tenant_entitlement_overrides,
-- not plan defaults. Connector and policy administration are gated by authorization roles, not by
-- additional entitlement keys.

-- 1. Defensive re-assert: keep the six existing AI capabilities enabled for supported plans.
INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, ed.key, true, NULL, now(), now()
FROM platform.plan_definitions pd
CROSS JOIN platform.entitlement_definitions ed
WHERE pd.code IN ('PRO', 'ENTERPRISE', 'DEMO', 'PILOT')
  AND ed.category = 'AI'
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;

-- 2. Introduce the AI Security pilot entitlement definition.
INSERT INTO platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at)
VALUES ('ai.security', 'AI_SECURITY', 'BOOLEAN',
        'Access the AI Security module (inventory, findings, policies)', now(), now())
ON CONFLICT (key) DO NOTHING;

-- 3. Seed ai.security DISABLED for every plan. Enablement is per-tenant via overrides (canary).
INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
SELECT pd.code, 'ai.security', false, NULL, now(), now()
FROM platform.plan_definitions pd
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;


-- source: V48__ai_security_platform_and_tenant_schema.sql
CREATE TABLE IF NOT EXISTS platform.ai_security_policy_distribution (
    policy_id varchar(128) PRIMARY KEY,
    available boolean NOT NULL DEFAULT true,
    default_enabled boolean NOT NULL DEFAULT true,
    updated_by varchar(255) NOT NULL DEFAULT 'system',
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled)
VALUES
    ('AWS_BEDROCK_PUBLIC_KB_S3', true, true),
    ('AWS_BEDROCK_UNAUTH_LAMBDA_URL', true, true),
    ('AWS_BEDROCK_WILDCARD_AGENT_ROLE', true, true),
    ('AWS_BEDROCK_WEAK_GUARDRAIL', true, true),
    ('AWS_BEDROCK_INVOCATION_LOGGING_DISABLED', true, true)
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 45;

UPDATE platform.tenant_schema_versions
SET target_version = 45,
    status = CASE WHEN current_version < 45 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 45;


-- source: V49__ai_security_azure_foundation.sql
INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled)
VALUES
    ('AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS', true, true),
    ('AZURE_AI_LOCAL_AUTH_ENABLED', true, true),
    ('AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED', true, true),
    ('AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED', true, false),
    ('AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED', true, true),
    ('AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED', true, true),
    ('AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH', false, false),
    ('AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY', true, true)
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.tenant_schema_versions
    ALTER COLUMN target_version SET DEFAULT 46;

UPDATE platform.tenant_schema_versions
SET target_version = 46,
    status = CASE WHEN current_version < 46 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 46;


-- source: V50__ai_grid_r0_catalog.sql
CREATE TABLE platform.ai_grid_technology_versions (
    technology_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    display_name varchar(255) NOT NULL,
    provider varchar(32) NOT NULL,
    lifecycle varchar(32) NOT NULL,
    aliases_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (technology_id, version)
);

CREATE TABLE platform.ai_grid_fact_definitions (
    fact_key varchar(255) NOT NULL,
    version varchar(32) NOT NULL,
    value_type varchar(32) NOT NULL,
    claim_semantics text NOT NULL,
    allowed_evidence_classes_json jsonb NOT NULL,
    allowed_workflow_uses_json jsonb NOT NULL,
    default_max_age_seconds bigint,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (fact_key, version)
);

CREATE TABLE platform.ai_grid_policy_versions (
    policy_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    name varchar(512) NOT NULL,
    description text NOT NULL,
    severity varchar(32) NOT NULL,
    lifecycle varchar(32) NOT NULL,
    workflow_class varchar(32) NOT NULL,
    default_selection varchar(32) NOT NULL,
    artifact_types_json jsonb NOT NULL,
    required_capabilities_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_relationships_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_resource_families_json jsonb NOT NULL,
    required_facts_json jsonb NOT NULL,
    predicate_json jsonb NOT NULL,
    reason_code varchar(128) NOT NULL,
    remediation text NOT NULL,
    framework_mappings_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    approved_by varchar(255),
    approved_at timestamptz,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version),
    CHECK (lifecycle IN ('DRAFT','VALIDATED','APPROVED','CANARY','PUBLISHED','RETIRED'))
);

INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES
    ('AWS_BEDROCK', '1.0.0', 'Amazon Bedrock', 'AWS', 'ACTIVE',
     '["BEDROCK_AGENTS","BEDROCK_GUARDRAILS","BEDROCK_KNOWLEDGE_BASES","BEDROCK_INVOCATION_LOGGING"]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('bedrock.agent.guardrail_attached_configured', '1.0.0', 'BOOLEAN',
     'Provider configuration states that the agent has an attached guardrail.', '["CONFIGURATION"]', '["POSTURE_FINDING"]', 86400),
    ('bedrock.guardrail.minimum_strength_configured', '1.0.0', 'STRING',
     'Minimum configured input/output strength across the attached guardrail content filters.', '["CONFIGURATION"]', '["POSTURE_FINDING"]', 86400),
    ('network.public_access_configured', '1.0.0', 'BOOLEAN',
     'Provider configuration permits public network access.', '["CONFIGURATION"]', '["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]', 86400),
    ('network.internet_reachability_verified', '1.0.0', 'BOOLEAN',
     'An approved reachability method verified an Internet path.', '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]', '["VALIDATED_EXPOSURE"]', 3600)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions (
    policy_id, version, name, description, severity, lifecycle, workflow_class,
    default_selection, artifact_types_json, required_relationships_json,
    required_resource_families_json, required_facts_json, predicate_json,
    reason_code, remediation, framework_mappings_json, approved_by, approved_at, published_at
) VALUES (
    'AWS_BEDROCK_WEAK_GUARDRAIL', '2.0.0', 'Weak attached guardrail content filters',
    'An attached Bedrock guardrail is configured below the approved minimum strength.',
    'HIGH', 'PUBLISHED', 'POSTURE_FINDING', 'REQUIRED', '["AI_AGENT"]', '["USES_GUARDRAIL"]',
    '["BEDROCK_AGENTS","BEDROCK_GUARDRAILS"]',
    '[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"bedrock.guardrail.minimum_strength_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
    '{"all":[{"fact":"bedrock.agent.guardrail_attached_configured","eq":true},{"fact":"bedrock.guardrail.minimum_strength_configured","in":["NONE","LOW"]}]}',
    'BEDROCK_GUARDRAIL_BELOW_APPROVED_STRENGTH',
    'Configure at least MEDIUM input and output strength for required harmful-content categories.',
    '{"OWASP_LLM_TOP_10":["LLM01"]}', 'ai-grid-bootstrap', now(), now()
) ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 48;
UPDATE platform.tenant_schema_versions
SET target_version = 48,
    status = CASE WHEN current_version < 48 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 48;


-- source: V51__ai_grid_r1_managed_ai_catalog.sql
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN native_kinds_json jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN scope_resolution varchar(32) NOT NULL DEFAULT 'STATIC';
ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_scope_resolution_check
    CHECK (scope_resolution IN ('STATIC','NATIVE_KIND_PLUS_STATIC'));

UPDATE platform.ai_grid_policy_versions
SET native_kinds_json = '["AWS_BEDROCK_AGENT"]'::jsonb
WHERE policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' AND version = '2.0.0';

CREATE UNIQUE INDEX uk_ai_grid_one_published_policy_version
    ON platform.ai_grid_policy_versions (policy_id)
    WHERE lifecycle = 'PUBLISHED';

INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES
    ('AZURE_AI_SERVICES', '1.0.0', 'Azure AI Services', 'AZURE', 'ACTIVE', '["AZURE_AI_ACCOUNTS","AZURE_DIAGNOSTIC_SETTINGS"]'),
    ('AZURE_AI_FOUNDRY', '1.0.0', 'Azure AI Foundry', 'AZURE', 'ACTIVE', '["AZURE_FOUNDRY_PROJECTS","AZURE_FOUNDRY_DEPLOYMENTS","AZURE_FOUNDRY_AGENTS","AZURE_FOUNDRY_AGENT_TOOLS"]'),
    ('AZURE_MACHINE_LEARNING', '1.0.0', 'Azure Machine Learning', 'AZURE', 'ACTIVE', '["AZURE_ML_WORKSPACES","AZURE_ML_MODELS","AZURE_ML_ENDPOINTS","AZURE_ML_DEPLOYMENTS","AZURE_ML_COMPUTE","AZURE_ML_JOBS","AZURE_ML_PIPELINES"]'),
    ('AZURE_AI_SEARCH', '1.0.0', 'Azure AI Search', 'AZURE', 'ACTIVE', '["AZURE_SEARCH_SERVICES","AZURE_SEARCH_INDEXES","AZURE_SEARCH_SKILLSETS","AZURE_SEARCH_INDEXERS","AZURE_SEARCH_DATA_SOURCES"]'),
    ('AZURE_BOT_SERVICE', '1.0.0', 'Azure Bot Service', 'AZURE', 'ACTIVE', '["AZURE_BOT_SERVICES","AZURE_BOT_CHANNELS","AZURE_BOT_IDENTITIES"]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES ('UNMAPPED_AI_TECHNOLOGY', '1.0.0', 'Unmapped AI technology', 'UNKNOWN', 'ACTIVE', '[]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('data.s3_public_access_configured','1.0.0','BOOLEAN','Provider configuration indicates that a knowledge-base S3 source is public.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('compute.lambda_url_auth_type_configured','1.0.0','STRING','Effective configured authentication type across agent action-group Lambda URLs.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.wildcard_permission_observed','1.0.0','BOOLEAN','A syntactic wildcard action was observed in the directly inspected execution-role policies.','["CONFIGURATION"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400),
    ('logging.model_invocation_enabled_configured','1.0.0','BOOLEAN','Bedrock model invocation logging is configured.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.local_auth_enabled_configured','1.0.0','BOOLEAN','Provider configuration permits key-based local authentication.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('logging.diagnostic_enabled_configured','1.0.0','BOOLEAN','An approved diagnostic logging destination is configured and enabled.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('agent.code_interpreter_enabled_configured','1.0.0','BOOLEAN','The agent configuration enables Code Interpreter.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.ml_endpoint_local_auth_enabled_configured','1.0.0','BOOLEAN','The Azure ML endpoint permits local key authentication.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.search_local_admin_auth_enabled_configured','1.0.0','BOOLEAN','Azure AI Search local admin-key authentication is enabled.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.search_data_source_non_identity_auth_observed','1.0.0','BOOLEAN','Authoritative configuration shows non-identity authentication for the Search data source.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.bot_password_without_managed_identity_observed','1.0.0','BOOLEAN','Bot password authentication is configured without an assigned managed identity.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.customer_managed_key_configured','1.0.0','BOOLEAN','Provider configuration declares customer-managed-key encryption.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('network.private_endpoint_count_configured','1.0.0','NUMBER','Number of configured private endpoint connections observed from provider configuration.','["CONFIGURATION"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400),
    ('owner.tag_candidate','1.0.0','OBJECT','Unverified ownership candidate derived from provider resource tags.','["CONFIGURATION"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400),
    ('agent.status_observed','1.0.0','STRING','Provider-reported lifecycle status for the AI agent.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('identity.execution_role_present_configured','1.0.0','BOOLEAN','Agent configuration contains a non-empty execution role identifier.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400)
ON CONFLICT DO NOTHING;

-- Publish only controls whose current collectors can normally produce exact verdict facts.
-- Search data-source authentication remains PREVIEW so its missing collection is visible without owner findings.
INSERT INTO platform.ai_grid_policy_versions (
    policy_id, version, name, description, severity, lifecycle, workflow_class, default_selection,
    artifact_types_json, native_kinds_json, required_resource_families_json, required_facts_json,
    predicate_json, reason_code, remediation, framework_mappings_json, scope_resolution,
    approved_by, approved_at, published_at
) VALUES
('AWS_BEDROCK_PUBLIC_KB_S3','2.0.0','Public knowledge-base S3 source','A Bedrock knowledge base uses a publicly accessible S3 source.','CRITICAL','PUBLISHED','POSTURE_FINDING','REQUIRED','["KNOWLEDGE_BASE"]','["AWS_BEDROCK_KNOWLEDGE_BASE"]','["BEDROCK_KNOWLEDGE_BASES","S3_EXPOSURE"]','[{"factKey":"data.s3_public_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.s3_public_access_configured","eq":true}','BEDROCK_KB_S3_PUBLIC','Block public access and restrict the bucket policy to the knowledge-base execution role.','{"OWASP_LLM_TOP_10":["LLM02","LLM08"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AWS_BEDROCK_UNAUTH_LAMBDA_URL','2.0.0','Unauthenticated action-group Lambda URL','An agent action group exposes a Lambda URL without IAM authentication.','CRITICAL','PUBLISHED','POSTURE_FINDING','REQUIRED','["AI_AGENT"]','["AWS_BEDROCK_AGENT"]','["BEDROCK_AGENTS","LAMBDA_URLS"]','[{"factKey":"compute.lambda_url_auth_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"compute.lambda_url_auth_type_configured","eq":"NONE"}','BEDROCK_LAMBDA_URL_UNAUTHENTICATED','Require AWS_IAM authentication or remove the function URL.','{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AWS_BEDROCK_WILDCARD_AGENT_ROLE','2.0.0','Wildcard agent execution-role actions','A syntactic wildcard action was observed in the agent execution role.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["AI_AGENT"]','["AWS_BEDROCK_AGENT"]','["BEDROCK_AGENTS","IAM_GLOBAL"]','[{"factKey":"identity.wildcard_permission_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.wildcard_permission_observed","eq":true}','BEDROCK_AGENT_ROLE_WILDCARD','Replace wildcard actions with minimum required actions and resources.','{"OWASP_LLM_TOP_10":["LLM06","LLM08"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AWS_BEDROCK_INVOCATION_LOGGING_DISABLED','2.0.0','Bedrock invocation logging disabled','Model invocation logging is disabled.','MEDIUM','PUBLISHED','POSTURE_FINDING','ENABLED','["ACCOUNT_CONFIGURATION"]','["AWS_BEDROCK_INVOCATION_LOGGING"]','["BEDROCK_INVOCATION_LOGGING"]','[{"factKey":"logging.model_invocation_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"logging.model_invocation_enabled_configured","eq":false}','BEDROCK_INVOCATION_LOGGING_DISABLED','Enable encrypted Bedrock model invocation logging.','{"OWASP_LLM_TOP_10":["LLM02"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS','2.0.0','Unrestricted Azure AI public access','A managed Azure AI resource permits unrestricted public network access.','CRITICAL','PUBLISHED','POSTURE_FINDING','REQUIRED','["OTHER_AI_ARTIFACT"]','["AZURE_AI_ACCOUNTS","AZURE_ML_WORKSPACES","AZURE_SEARCH_SERVICES"]','[]','[{"factKey":"network.public_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"network.public_access_configured","eq":true}','AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS','Disable public access or restrict network ACLs and use approved private endpoints.','{"OWASP_LLM_TOP_10":["LLM02","LLM06"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_AI_LOCAL_AUTH_ENABLED','2.0.0','Azure AI local authentication enabled','An Azure AI account permits key-based local authentication.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["OTHER_AI_ARTIFACT"]','["AZURE_AI_ACCOUNTS"]','[]','[{"factKey":"identity.local_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.local_auth_enabled_configured","eq":true}','AZURE_AI_LOCAL_AUTH_ENABLED','Disable local authentication and require Microsoft Entra identities.','{"OWASP_LLM_TOP_10":["LLM06"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED','2.0.0','Azure AI diagnostic logging disabled','An Azure AI account has no enabled diagnostic-log destination.','MEDIUM','PUBLISHED','POSTURE_FINDING','ENABLED','["OTHER_AI_ARTIFACT"]','["AZURE_AI_ACCOUNTS"]','["AZURE_DIAGNOSTIC_SETTINGS"]','[{"factKey":"logging.diagnostic_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"logging.diagnostic_enabled_configured","eq":false}','AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED','Enable diagnostic logs to an approved destination.','{"OWASP_LLM_TOP_10":["LLM02"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED','2.0.0','Foundry agent Code Interpreter enabled','A Foundry agent enables Code Interpreter.','HIGH','PUBLISHED','POSTURE_FINDING','PREVIEW','["AI_AGENT"]','["AZURE_FOUNDRY_AGENTS"]','[]','[{"factKey":"agent.code_interpreter_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"agent.code_interpreter_enabled_configured","eq":true}','AZURE_FOUNDRY_CODE_INTERPRETER_ENABLED','Disable Code Interpreter unless explicitly approved.','{"OWASP_LLM_TOP_10":["LLM06"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED','2.0.0','Azure ML endpoint local authentication enabled','An Azure ML endpoint permits local key authentication.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["OTHER_AI_ARTIFACT"]','["AZURE_ML_ENDPOINTS"]','[]','[{"factKey":"identity.ml_endpoint_local_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.ml_endpoint_local_auth_enabled_configured","eq":true}','AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED','Require Microsoft Entra authentication.','{"OWASP_LLM_TOP_10":["LLM06"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED','2.0.0','Azure AI Search local admin authentication enabled','An Azure AI Search service permits local admin-key authentication.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["OTHER_AI_ARTIFACT"]','["AZURE_SEARCH_SERVICES"]','[]','[{"factKey":"identity.search_local_admin_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.search_local_admin_auth_enabled_configured","eq":true}','AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED','Disable local authentication and use Entra RBAC.','{"OWASP_LLM_TOP_10":["LLM06","LLM08"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH','2.0.0','Azure AI Search data source does not use identity authentication','Search data-source authentication is not identity based.','HIGH','PUBLISHED','POSTURE_FINDING','PREVIEW','["OTHER_AI_ARTIFACT"]','["AZURE_SEARCH_DATA_SOURCES"]','[]','[{"factKey":"identity.search_data_source_non_identity_auth_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.search_data_source_non_identity_auth_observed","eq":true}','AZURE_SEARCH_NON_IDENTITY_AUTH','Use a managed identity for the Search data-source connection.','{"OWASP_LLM_TOP_10":["LLM06","LLM08"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY','2.0.0','Azure Bot password authentication without managed identity','An Azure Bot uses password authentication without a managed identity.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["AI_AGENT"]','["AZURE_BOT_SERVICES"]','["AZURE_BOT_IDENTITIES"]','[{"factKey":"identity.bot_password_without_managed_identity_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.bot_password_without_managed_identity_observed","eq":true}','AZURE_BOT_PASSWORD_WITHOUT_MANAGED_IDENTITY','Assign a managed identity and remove password credentials.','{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AWS_BEDROCK_GUARDRAIL_NOT_ATTACHED','1.0.0','No guardrail attached to Bedrock agent','A Bedrock agent has no configured guardrail association.','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["AI_AGENT"]','["AWS_BEDROCK_AGENT"]','["BEDROCK_AGENTS"]','[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"bedrock.agent.guardrail_attached_configured","eq":false}','BEDROCK_GUARDRAIL_NOT_ATTACHED','Attach an approved Bedrock guardrail to every production agent path.','{"OWASP_LLM_TOP_10":["LLM01","LLM05"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AWS_BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING','1.0.0','Bedrock agent inactive or missing execution role','The agent is not prepared or has no configured execution role.','MEDIUM','PUBLISHED','POSTURE_FINDING','PREVIEW','["AI_AGENT"]','["AWS_BEDROCK_AGENT"]','["BEDROCK_AGENTS"]','[{"factKey":"agent.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"identity.execution_role_present_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"fact":"agent.status_observed","neq":"PREPARED"},{"fact":"identity.execution_role_present_configured","eq":false}]}','BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING','Prepare the agent and configure its least-privileged execution role.','{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_AI_PRIVATE_ENDPOINT_MISSING','1.0.0','Azure AI private endpoint missing','No private endpoint connection is configured for the managed AI resource.','MEDIUM','PUBLISHED','POSTURE_FINDING','PREVIEW','["OTHER_AI_ARTIFACT"]','["AZURE_AI_ACCOUNTS"]','[]','[{"factKey":"network.private_endpoint_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"network.private_endpoint_count_configured","eq":0}','AZURE_AI_PRIVATE_ENDPOINT_MISSING','Configure an approved private endpoint and restrict public network access.','{"OWASP_LLM_TOP_10":["LLM02"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now()),
('AZURE_AI_CUSTOMER_MANAGED_KEY_MISSING','1.0.0','Azure AI customer-managed-key encryption missing','The Azure AI account is not configured with a customer-managed encryption key.','MEDIUM','PUBLISHED','POSTURE_FINDING','ENABLED','["OTHER_AI_ARTIFACT"]','["AZURE_AI_ACCOUNTS"]','[]','[{"factKey":"data.customer_managed_key_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.customer_managed_key_configured","eq":false}','AZURE_AI_CUSTOMER_MANAGED_KEY_MISSING','Configure encryption with a customer-managed key in an approved Key Vault.','{"OWASP_LLM_TOP_10":["LLM02","LLM03"]}','NATIVE_KIND_PLUS_STATIC','ai-grid-r1-bootstrap',now(),now())
ON CONFLICT DO NOTHING;


-- source: V52__ai_grid_r1_tenant_schema_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 49;
UPDATE platform.tenant_schema_versions
SET target_version = 49,
    status = CASE WHEN current_version < 49 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 49;



-- source: V53__ai_grid_answer_key_precision_governance.sql
CREATE TABLE platform.ai_grid_answer_key_environments (
    id uuid PRIMARY KEY,
    environment_key varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    provider varchar(32) NOT NULL,
    resource_family varchar(128) NOT NULL,
    lifecycle varchar(32) NOT NULL DEFAULT 'DRAFT',
    engineering_owner varchar(255) NOT NULL,
    security_reviewer varchar(255) NOT NULL,
    provider_api_versions_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    expected_economics_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    change_summary text NOT NULL,
    certified_at timestamptz,
    last_verified_at timestamptz,
    review_due_at timestamptz NOT NULL,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_key, version),
    CHECK (lifecycle IN ('DRAFT','CERTIFIED','STALE','RETIRED')),
    CHECK (review_due_at > created_at)
);

CREATE UNIQUE INDEX uk_ai_grid_answer_key_certified_version
    ON platform.ai_grid_answer_key_environments (environment_key)
    WHERE lifecycle = 'CERTIFIED';

CREATE TABLE platform.ai_grid_answer_key_cases (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL REFERENCES platform.ai_grid_answer_key_environments(id),
    case_key varchar(160) NOT NULL,
    scenario varchar(32) NOT NULL,
    policy_id varchar(128),
    policy_version varchar(32),
    expected_applicability varchar(32),
    expected_decision varchar(32),
    expected_finding boolean,
    expected_json jsonb NOT NULL,
    label_version varchar(32) NOT NULL,
    rationale text NOT NULL,
    evidence_reference text NOT NULL,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_id, case_key),
    CHECK (scenario IN ('SECURE','INSECURE','PARTIAL','DENIED','THROTTLED','STALE','UNSUPPORTED',
                        'DELETED','RENAMED','SPLIT','MERGE','REDISCOVERED','PROXY_VS_VERIFIED','OTHER')),
    CHECK (expected_applicability IS NULL OR expected_applicability IN ('APPLICABLE','NOT_APPLICABLE')),
    CHECK (expected_decision IS NULL OR expected_decision IN ('PASS','FAIL','NO_DECISION')),
    CHECK ((policy_id IS NULL AND policy_version IS NULL) OR
           (policy_id IS NOT NULL AND policy_version IS NOT NULL))
);

CREATE TABLE platform.ai_grid_answer_key_runs (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL REFERENCES platform.ai_grid_answer_key_environments(id),
    catalog_digest varchar(128) NOT NULL,
    status varchar(32) NOT NULL,
    total_cases integer NOT NULL,
    matched_cases integer NOT NULL,
    executed_by varchar(255) NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status IN ('PASS','FAIL')),
    CHECK (total_cases > 0),
    CHECK (matched_cases >= 0 AND matched_cases <= total_cases)
);

CREATE TABLE platform.ai_grid_answer_key_results (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES platform.ai_grid_answer_key_runs(id),
    case_id uuid NOT NULL REFERENCES platform.ai_grid_answer_key_cases(id),
    observed_json jsonb NOT NULL,
    matched boolean NOT NULL,
    mismatch_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, case_id)
);

CREATE INDEX idx_ai_grid_answer_key_run_environment
    ON platform.ai_grid_answer_key_runs (environment_id, completed_at DESC);

CREATE TABLE platform.ai_grid_precision_reviews (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    population_definition text NOT NULL,
    sampling_method text NOT NULL,
    minimum_sample_size integer NOT NULL,
    confidence_level double precision NOT NULL,
    precision_threshold double precision NOT NULL DEFAULT 0.95,
    material_change_digest varchar(128) NOT NULL,
    bias_status varchar(32) NOT NULL DEFAULT 'PENDING',
    bias_rationale text,
    bias_reviewed_by varchar(255),
    status varchar(32) NOT NULL DEFAULT 'DRAFT',
    resolved_positive_samples integer NOT NULL DEFAULT 0,
    true_positives integer NOT NULL DEFAULT 0,
    false_positives integer NOT NULL DEFAULT 0,
    precision_value double precision,
    confidence_lower double precision,
    confidence_upper double precision,
    finalized_at timestamptz,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_id, policy_version, material_change_digest),
    CHECK (minimum_sample_size > 0),
    CHECK (confidence_level > 0 AND confidence_level < 1),
    CHECK (precision_threshold >= 0 AND precision_threshold <= 1),
    CHECK (bias_status IN ('PENDING','PASSED','FAILED')),
    CHECK (status IN ('DRAFT','IN_REVIEW','ADJUDICATION','PASSED','FAILED','STALE'))
);

CREATE TABLE platform.ai_grid_precision_samples (
    id uuid PRIMARY KEY,
    review_id uuid NOT NULL REFERENCES platform.ai_grid_precision_reviews(id),
    sample_key varchar(160) NOT NULL,
    provider varchar(32) NOT NULL,
    resource_family varchar(128) NOT NULL,
    severity varchar(32) NOT NULL,
    observed_outcome varchar(32) NOT NULL,
    predicted_finding boolean NOT NULL,
    evidence_reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (review_id, sample_key),
    CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    CHECK (observed_outcome IN ('PASS','FAIL','NO_DECISION','NOT_APPLICABLE'))
);

CREATE TABLE platform.ai_grid_precision_labels (
    id uuid PRIMARY KEY,
    sample_id uuid NOT NULL REFERENCES platform.ai_grid_precision_samples(id),
    reviewer varchar(255) NOT NULL,
    label varchar(32) NOT NULL,
    label_version varchar(32) NOT NULL,
    rationale text NOT NULL,
    evidence_reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (sample_id, reviewer),
    CHECK (label IN ('TRUE_POSITIVE','FALSE_POSITIVE','TRUE_NEGATIVE','FALSE_NEGATIVE','EXCLUDE'))
);

CREATE TABLE platform.ai_grid_precision_adjudications (
    id uuid PRIMARY KEY,
    sample_id uuid NOT NULL UNIQUE REFERENCES platform.ai_grid_precision_samples(id),
    final_label varchar(32) NOT NULL,
    rationale text NOT NULL,
    adjudicated_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (final_label IN ('TRUE_POSITIVE','FALSE_POSITIVE','TRUE_NEGATIVE','FALSE_NEGATIVE','EXCLUDE'))
);

CREATE TABLE platform.ai_grid_policy_release_decisions (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    decision varchar(32) NOT NULL,
    answer_key_run_id uuid REFERENCES platform.ai_grid_answer_key_runs(id),
    precision_review_id uuid REFERENCES platform.ai_grid_precision_reviews(id),
    reason text NOT NULL,
    decided_by varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CHECK (decision IN ('APPROVED','BLOCKED'))
);

CREATE INDEX idx_ai_grid_precision_review_policy
    ON platform.ai_grid_precision_reviews (policy_id, policy_version, created_at DESC);
CREATE INDEX idx_ai_grid_precision_sample_review
    ON platform.ai_grid_precision_samples (review_id);
CREATE INDEX idx_ai_grid_precision_label_sample
    ON platform.ai_grid_precision_labels (sample_id);
CREATE INDEX idx_ai_grid_release_decision_policy
    ON platform.ai_grid_policy_release_decisions (policy_id, policy_version, decided_at DESC);


-- source: V54__ai_grid_budget_tenant_schema_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 50;
UPDATE platform.tenant_schema_versions
SET target_version = 50,
    status = CASE WHEN current_version < 50 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 50;


-- source: V55__ai_grid_integrity_tenant_schema_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 51;
UPDATE platform.tenant_schema_versions
SET target_version = 51,
    status = CASE WHEN current_version < 51 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 51;



-- source: V56__ai_grid_r1_validation_provenance.sql
-- R1 answer-key runs must be tied to immutable tenant evidence, not caller-authored JSON alone.

ALTER TABLE platform.ai_grid_answer_key_runs
    ADD COLUMN source_tenant_id uuid REFERENCES platform.tenants(id),
    ADD COLUMN source_run_id uuid,
    ADD COLUMN provenance_state varchar(32) NOT NULL DEFAULT 'EXTERNAL_ATTESTATION';

ALTER TABLE platform.ai_grid_answer_key_runs
    ADD CONSTRAINT ai_grid_answer_key_run_provenance_state_check
    CHECK (provenance_state IN ('EXTERNAL_ATTESTATION','PLATFORM_RUN_BOUND'));

ALTER TABLE platform.ai_grid_answer_key_results
    ADD COLUMN source_assessment_id uuid,
    ADD COLUMN source_decision_fingerprint varchar(64);

CREATE INDEX idx_ai_grid_answer_key_run_source
    ON platform.ai_grid_answer_key_runs (source_tenant_id, source_run_id, completed_at DESC);



-- source: V57__ai_grid_r1_minimum_context_and_tenant_target.sql
-- Exact claim keys prevent baseline proxies from satisfying verified context requirements.

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('identity.effective_admin_access_derived','1.0.0','BOOLEAN',
     'Effective administrative access derived from an approved identity graph and authorization model.',
     '["GRAPH_ANALYSIS"]','["EXPOSURE_HYPOTHESIS","VALIDATED_EXPOSURE"]',3600),
    ('data.source_linked','1.0.0','BOOLEAN',
     'A provider or graph relationship links the AI artifact to a data source; this does not classify content.',
     '["RELATIONSHIP_GRAPH"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400),
    ('data.sensitive_content_confirmed','1.0.0','BOOLEAN',
     'An approved data-classification method confirmed sensitive content reachable from the AI system.',
     '["DATA_CLASSIFICATION","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
    ('owner.confirmed','1.0.0','OBJECT',
     'An authorized user or approved service-catalog mapping confirmed the accountable owner.',
     '["USER_ASSERTION","SERVICE_CATALOG"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',null)
ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 52;
UPDATE platform.tenant_schema_versions
SET target_version = 52,
    status = CASE WHEN current_version < 52 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 52;



-- source: V58__ai_grid_r1_azure_rai_policy_slice.sql
INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES
    ('AZURE_AI_SERVICES', '1.1.0', 'Azure AI Services', 'AZURE', 'ACTIVE',
     '["AZURE_AI_ACCOUNTS","AZURE_DIAGNOSTIC_SETTINGS","AZURE_RAI_POLICIES"]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('guardrail.rai_non_blocking_filter_observed','1.0.0','BOOLEAN',
     'Every returned RAI content-filter entry had explicit enabled and blocking booleans; true means at least one entry was disabled or non-blocking.',
     '["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('guardrail.rai_policy_reference_configured','1.0.0','STRING',
     'Provider configuration names the RAI policy associated with an Azure model deployment.',
     '["CONFIGURATION"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions (
    policy_id, version, name, description, severity, lifecycle, workflow_class, default_selection,
    artifact_types_json, native_kinds_json, required_resource_families_json, required_facts_json,
    predicate_json, reason_code, remediation, framework_mappings_json, scope_resolution,
    approved_by, approved_at, published_at
) VALUES (
    'AZURE_RAI_POLICY_NON_BLOCKING_FILTER','1.0.0','Azure RAI policy contains a non-blocking filter',
    'An Azure RAI policy explicitly disables a returned content filter or configures it as non-blocking.',
    'HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["AI_GUARDRAIL"]','["AZURE_RAI_POLICIES"]',
    '["AZURE_RAI_POLICIES"]',
    '[{"factKey":"guardrail.rai_non_blocking_filter_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
    '{"fact":"guardrail.rai_non_blocking_filter_observed","eq":true}',
    'AZURE_RAI_FILTER_DISABLED_OR_NON_BLOCKING',
    'Enable blocking for every explicitly configured RAI content filter. Review category and threshold completeness separately.',
    '{"OWASP_LLM_TOP_10":["LLM01","LLM09"]}','STATIC','ai-grid-r1-azure-rai-slice',now(),now()
) ON CONFLICT DO NOTHING;


-- source: V59__ai_grid_r1_release_certification.sql
CREATE TABLE platform.ai_grid_release_gate_evidence (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    gate_code varchar(96) NOT NULL,
    status varchar(16) NOT NULL,
    evidence_reference text NOT NULL,
    rationale text NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_by varchar(255) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (status IN ('PASS','FAIL')),
    CHECK (valid_until > recorded_at)
);

CREATE INDEX idx_ai_grid_release_gate_latest
    ON platform.ai_grid_release_gate_evidence (release_id, gate_code, recorded_at DESC);

CREATE TABLE platform.ai_grid_release_decisions (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    decision varchar(16) NOT NULL,
    gate_snapshot_json jsonb NOT NULL,
    reason text NOT NULL,
    decided_by varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (decision IN ('APPROVED','BLOCKED'))
);

CREATE INDEX idx_ai_grid_release_decision_latest
    ON platform.ai_grid_release_decisions (release_id, decided_at DESC);


-- source: V60__ai_grid_current_coverage_tenant_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 53;
UPDATE platform.tenant_schema_versions
SET target_version = 53,
    status = CASE WHEN current_version < 53 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 53;


-- source: V61__ai_grid_r1_operational_evidence_digest.sql
-- Operational release evidence is valid only for the connector/catalog material that produced it.
ALTER TABLE platform.ai_grid_release_gate_evidence
    ADD COLUMN material_digest varchar(64);

CREATE INDEX idx_ai_grid_release_gate_material
    ON platform.ai_grid_release_gate_evidence (release_id, gate_code, material_digest, recorded_at DESC);


-- source: V62__ai_grid_hardening_tenant_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 55;
UPDATE platform.tenant_schema_versions
SET target_version = 55,
    status = CASE WHEN current_version < 55 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 55;


-- source: V63__ai_grid_r2_correlation_catalog.sql
CREATE TABLE platform.ai_grid_correlation_versions (
    correlation_id varchar(128) NOT NULL,
    version varchar(32) NOT NULL,
    name varchar(512) NOT NULL,
    description text NOT NULL,
    lifecycle varchar(32) NOT NULL CHECK (lifecycle IN ('DRAFT','APPROVED','PUBLISHED','RETIRED')),
    severity varchar(32) NOT NULL,
    precision_threshold double precision NOT NULL CHECK (precision_threshold BETWEEN 0 AND 1),
    max_path_depth integer NOT NULL CHECK (max_path_depth BETWEEN 1 AND 6),
    max_fan_out integer NOT NULL CHECK (max_fan_out BETWEEN 1 AND 100),
    allowed_node_types_json jsonb NOT NULL,
    allowed_edge_types_json jsonb NOT NULL,
    requirements_json jsonb NOT NULL,
    approved_by varchar(255),
    approved_at timestamptz,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (correlation_id, version)
);

CREATE TABLE platform.ai_grid_correlation_precision_reviews (
    id uuid PRIMARY KEY,
    correlation_id varchar(128) NOT NULL,
    correlation_version varchar(32) NOT NULL,
    material_digest varchar(128) NOT NULL,
    sample_size integer NOT NULL CHECK (sample_size > 0),
    accepted_samples integer NOT NULL CHECK (accepted_samples >= 0),
    precision_value double precision NOT NULL CHECK (precision_value BETWEEN 0 AND 1),
    precision_threshold double precision NOT NULL CHECK (precision_threshold BETWEEN 0 AND 1),
    status varchar(32) NOT NULL CHECK (status IN ('PASSED','FAILED','STALE')),
    evidence_reference varchar(1024) NOT NULL,
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (correlation_id, correlation_version)
        REFERENCES platform.ai_grid_correlation_versions(correlation_id, version),
    UNIQUE (correlation_id, correlation_version, material_digest)
);

INSERT INTO platform.ai_grid_correlation_versions
    (correlation_id, version, name, description, lifecycle, severity, precision_threshold,
     max_path_depth, max_fan_out, allowed_node_types_json, allowed_edge_types_json,
     requirements_json, approved_by, approved_at, published_at)
VALUES
('R2_EXTERNAL_SENSITIVE_ACCESS','1.0.0','Externally reachable AI path to sensitive data',
 'Verified external reachability, inadequate authentication, and confirmed sensitive-data access.',
 'PUBLISHED','CRITICAL',0.95,6,100,
 '["AI_AGENT","AI_MODEL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_MODEL","USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","READS_FROM_S3","USES_SEARCH_INDEX","DEPLOYS_MODEL","HAS_DEPLOYMENT","INVOKES_LAMBDA"]',
 '{"validated":["network.internet_reachability_verified","identity.inadequate_authentication_verified","data.sensitive_access_confirmed"],"hypothesis":["network.public_access_configured","identity.local_auth_enabled_configured","data.source_linked"]}',
 'ai-grid-bootstrap',now(),now()),
('R2_EXCESSIVE_TOOL_PRIVILEGE','1.0.0','Tool-enabled agent with excessive privilege',
 'Tool-enabled agent with derived excessive effective privilege and secret or consequential-action access.',
 'PUBLISHED','HIGH',0.93,6,100,
 '["AI_AGENT","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","INVOKES_LAMBDA","ASSUMES_ROLE","HAS_ROLE_ASSIGNMENT","USES_KEY_VAULT_KEY"]',
 '{"validated":["identity.effective_excessive_privilege_derived","impact.secret_or_consequential_access_confirmed"],"hypothesis":["identity.wildcard_permission_observed"]}',
 'ai-grid-bootstrap',now(),now()),
('R2_UNTRUSTED_AUTONOMOUS_EXECUTION','1.0.0','Untrusted input to inadequately controlled autonomous execution',
 'Untrusted input or retrieval reaches autonomous execution without adequate guardrail, isolation, or approval.',
 'PUBLISHED','HIGH',0.92,6,100,
 '["AI_AGENT","AI_GUARDRAIL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","INVOKES_LAMBDA","USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","USES_SEARCH_INDEX","USES_GUARDRAIL"]',
 '{"validated":["input.untrusted_path_verified","agent.autonomous_execution_verified","control.execution_boundary_inadequate_verified"],"hypothesis":["data.source_linked","agent.code_interpreter_enabled_configured","bedrock.agent.guardrail_attached_configured"]}',
 'ai-grid-bootstrap',now(),now())
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,
     allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('identity.inadequate_authentication_verified','1.0.0','BOOLEAN',
 'An approved identity analysis verified inadequate authentication on the exposure entry path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('data.sensitive_access_confirmed','1.0.0','BOOLEAN',
 'Approved data-security evidence confirms that the path can access sensitive data.',
 '["DSPM","GRAPH_ANALYSIS","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('identity.effective_excessive_privilege_derived','1.0.0','BOOLEAN',
 'A versioned identity graph derived excessive effective privilege.',
 '["GRAPH_ANALYSIS"]','["VALIDATED_EXPOSURE"]',3600),
('impact.secret_or_consequential_access_confirmed','1.0.0','BOOLEAN',
 'Approved evidence confirms secret access or a consequential action.',
 '["CIEM","GRAPH_ANALYSIS","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('input.untrusted_path_verified','1.0.0','BOOLEAN',
 'An approved method verified an untrusted input or retrieval path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('agent.autonomous_execution_verified','1.0.0','BOOLEAN',
 'Approved evidence verifies autonomous execution on the path.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('control.execution_boundary_inadequate_verified','1.0.0','BOOLEAN',
 'Approved evidence verifies inadequate guardrail, isolation, or approval controls.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600)
ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 56;
UPDATE platform.tenant_schema_versions
SET target_version = 56,
    status = CASE WHEN current_version < 56 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 56;


-- source: V64__ai_grid_r2_completion_contract.sql
UPDATE platform.tenant_schema_versions
SET target_version = 57,
    status = CASE WHEN current_version < 57 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 57;
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 57;


-- source: V65__ai_grid_r2_release_manifest.sql
CREATE TABLE platform.ai_grid_release_manifest_items (
    release_id varchar(32) NOT NULL,
    subject_type varchar(32) NOT NULL,
    subject_id varchar(128) NOT NULL,
    subject_version varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, subject_type, subject_id, subject_version),
    CHECK (subject_type IN ('CORRELATION','POLICY'))
);

ALTER TABLE platform.ai_grid_precision_reviews
    ADD COLUMN label_set_version varchar(32) NOT NULL DEFAULT 'R1-LEGACY',
    ADD COLUMN answer_key_run_id uuid REFERENCES platform.ai_grid_answer_key_runs(id);

INSERT INTO platform.ai_grid_release_manifest_items
    (release_id,subject_type,subject_id,subject_version)
VALUES
    ('R2','CORRELATION','R2_EXTERNAL_SENSITIVE_ACCESS','1.0.0'),
    ('R2','CORRELATION','R2_EXCESSIVE_TOOL_PRIVILEGE','1.0.0'),
    ('R2','CORRELATION','R2_UNTRUSTED_AUTONOMOUS_EXECUTION','1.0.0')
ON CONFLICT DO NOTHING;

CREATE FUNCTION platform.reject_ai_grid_release_manifest_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'AI Grid release manifests are immutable';
END $$;

CREATE TRIGGER ai_grid_release_manifest_immutable
BEFORE UPDATE OR DELETE ON platform.ai_grid_release_manifest_items
FOR EACH ROW EXECUTE FUNCTION platform.reject_ai_grid_release_manifest_mutation();

UPDATE platform.tenant_schema_versions
SET target_version=59,status=case when current_version<59 then 'PENDING' else status end,updated_at=now()
WHERE target_version<59;
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 59;


-- source: V66__ai_security_rai_policy_distribution.sql
INSERT INTO platform.ai_security_policy_distribution (
    policy_id,
    available,
    default_enabled,
    updated_by
)
VALUES (
    'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    true,
    true,
    'ai-security-policy-registry'
)
ON CONFLICT (policy_id) DO NOTHING;


-- source: V67__ai_grid_policy_catalog_distribution.sql
-- Canonical platform release and distribution state.  It is intentionally
-- independent of tenant selection and policy lifecycle.
CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_distribution (
    policy_id varchar(128) PRIMARY KEY,
    available boolean NOT NULL DEFAULT true,
    default_selection varchar(32) NOT NULL DEFAULT 'ENABLED',
    rollout_stage varchar(32) NOT NULL DEFAULT 'GENERAL_AVAILABILITY',
    canary_tenant_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    pinned_version varchar(32),
    updated_by varchar(255) NOT NULL DEFAULT 'ai-grid-bootstrap',
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (default_selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    CHECK (rollout_stage IN ('GENERAL_AVAILABILITY','CANARY','PAUSED','RETIRED'))
);

ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS package_digest varchar(64),
    ADD COLUMN IF NOT EXISTS package_source_ref varchar(1024),
    ADD COLUMN IF NOT EXISTS authored_by varchar(255),
    ADD COLUMN IF NOT EXISTS release_notes text,
    ADD COLUMN IF NOT EXISTS replaces_policy_id varchar(128),
    ADD COLUMN IF NOT EXISTS replaces_version varchar(32);

UPDATE platform.ai_grid_policy_versions
   SET authored_by = coalesce(authored_by, approved_by, 'ai-grid-bootstrap')
 WHERE authored_by IS NULL;

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id, available, default_selection, rollout_stage, updated_by)
SELECT DISTINCT ON (policy_id)
       policy_id, true, default_selection, 'GENERAL_AVAILABILITY', 'ai-grid-catalog-migration'
  FROM platform.ai_grid_policy_versions
 WHERE lifecycle = 'PUBLISHED'
 ORDER BY policy_id, published_at DESC NULLS LAST, version DESC
ON CONFLICT (policy_id) DO NOTHING;

-- Keep the legacy distribution populated during the staged migration.  The
-- governed catalog is authoritative for new reads and evaluations.
INSERT INTO platform.ai_security_policy_distribution (policy_id, available, default_enabled, updated_by)
SELECT policy_id, available, default_selection IN ('REQUIRED','ENABLED'), 'ai-grid-catalog-migration'
  FROM platform.ai_grid_policy_distribution
ON CONFLICT (policy_id) DO NOTHING;


-- source: V68__ai_grid_policy_migration_target.sql
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 61;
UPDATE platform.tenant_schema_versions
   SET target_version = 61,
       status = CASE WHEN current_version < 61 THEN 'PENDING' ELSE status END,
       updated_at = now()
 WHERE target_version < 61;


-- source: V69__ai_grid_policy_portfolio.sql
CREATE TABLE platform.ai_grid_policy_candidates (
    id uuid PRIMARY KEY,
    title varchar(512) NOT NULL,
    source_type varchar(64) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'INTAKE',
    technology_id varchar(128),
    rationale text NOT NULL,
    framework_mappings_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    risk_score integer NOT NULL CHECK (risk_score BETWEEN 1 AND 5),
    reach_score integer NOT NULL CHECK (reach_score BETWEEN 1 AND 5),
    evidence_maturity integer NOT NULL CHECK (evidence_maturity BETWEEN 1 AND 5),
    remediation_clarity integer NOT NULL CHECK (remediation_clarity BETWEEN 1 AND 5),
    owner varchar(255),
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (source_type IN ('CONNECTOR_CAPABILITY','COVERAGE_GAP','THREAT_RESEARCH','CUSTOMER_REQUEST','INCIDENT','COMPLIANCE_FRAMEWORK','DESIGN_PARTNER')),
    CHECK (status IN ('INTAKE','RESEARCH','COLLECTOR_BACKLOG','READY_FOR_AUTHORING','DECLINED','SHIPPED'))
);


-- source: V70__ai_grid_generic_policy_parameters.sql
ALTER TABLE platform.ai_grid_policy_versions ADD COLUMN IF NOT EXISTS parameter_definitions_json jsonb NOT NULL DEFAULT '[]'::jsonb;
UPDATE platform.ai_grid_policy_versions
   SET parameter_definitions_json='[{"key":"minimumGuardrailStrength","type":"ENUM","options":["NONE","LOW","MEDIUM","HIGH"],"defaultValue":"MEDIUM"}]'::jsonb,
       predicate_json='{"all":[{"fact":"bedrock.agent.guardrail_attached_configured","eq":true},{"fact":"bedrock.guardrail.minimum_strength_configured","strength_lt":{"parameter":"minimumGuardrailStrength"}}]}'::jsonb
 WHERE policy_id='AWS_BEDROCK_WEAK_GUARDRAIL' AND version='2.0.0';


-- source: V71__ai_grid_one_time_test_reset.sql
-- Records the deliberately irreversible, one-time clean-slate operation.
CREATE TABLE IF NOT EXISTS platform.ai_grid_test_data_reset_log (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    reset_by varchar(255) NOT NULL,
    reset_at timestamptz NOT NULL DEFAULT now(),
    tenant_count integer NOT NULL,
    confirmation_digest varchar(64) NOT NULL
);


-- source: V72__ai_grid_knowledge_mcp_preview_policies.sql
-- Conservative preview controls: every predicate requires direct provider configuration facts.
INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('mcp.endpoint_exposure','1.0.0','STRING','Provider configuration reports an MCP endpoint exposure classification.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.configured_auth_type','1.0.0','STRING','Provider configuration reports MCP authentication classification without credentials or headers.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.target_status','1.0.0','STRING','Provider control plane reports the managed MCP target status.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.sensitivity_confirmed','1.0.0','BOOLEAN','Macie or Purview confirmed sensitive content for the data store.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.public_content_access_configured','1.0.0','BOOLEAN','Provider configuration confirms that data content is publicly accessible.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions
    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,
     artifact_types_json,native_kinds_json,required_resource_families_json,required_facts_json,predicate_json,
     reason_code,remediation,framework_mappings_json,scope_resolution,approved_by,approved_at,published_at)
VALUES
('MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH','1.0.0','Public MCP endpoint without configured authentication',
 'A provider explicitly confirms public network reachability and reports no configured authentication; an external URL alone yields no decision.',
 'CRITICAL','PUBLISHED','POSTURE_FINDING','PREVIEW','["MCP_SERVER"]','[]','[]',
 '[{"factKey":"mcp.endpoint_exposure","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"mcp.configured_auth_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"all":[{"fact":"mcp.endpoint_exposure","eq":"PUBLIC_NETWORK_REACHABLE"},{"fact":"mcp.configured_auth_type","eq":"NONE"}]}',
 'MCP_PUBLIC_ENDPOINT_NO_AUTH','Configure an approved authentication mechanism before exposing the MCP endpoint.',
 '{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now()),
('MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL','1.0.0','MCP target unhealthy or synchronization unsuccessful',
 'A provider-managed MCP target reports a failed terminal or unsuccessful synchronization state.',
 'MEDIUM','PUBLISHED','POSTURE_FINDING','PREVIEW','["MCP_TARGET"]','[]','["AWS_AGENTCORE_GATEWAY_TARGETS"]',
 '[{"factKey":"mcp.target_status","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"fact":"mcp.target_status","in":["FAILED","UPDATE_UNSUCCESSFUL","SYNCHRONIZE_UNSUCCESSFUL"]}',
 'MCP_TARGET_UNHEALTHY','Repair the target configuration and confirm a successful provider synchronization.',
 '{"OWASP_LLM_TOP_10":["LLM06"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now()),
('SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS','1.0.0','Sensitive AI data source with public content access',
 'A provider-confirmed sensitive data store is also provider-confirmed to allow public content access.',
 'CRITICAL','PUBLISHED','POSTURE_FINDING','PREVIEW','["DATA_STORE"]','[]','["AWS_MACIE_PII","S3_EXPOSURE"]',
 '[{"factKey":"data.sensitivity_confirmed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"data.public_content_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
 '{"all":[{"fact":"data.sensitivity_confirmed","eq":true},{"fact":"data.public_content_access_configured","eq":true}]}',
 'SENSITIVE_DATA_PUBLIC_CONTENT','Restrict content access and verify the data-store policy no longer allows public reads.',
 '{"OWASP_LLM_TOP_10":["LLM02"]}','STATIC','ai-grid-knowledge-mcp-preview',now(),now())
ON CONFLICT DO NOTHING;


-- source: V73__ai_grid_knowledge_mcp_normalized_facts.sql
-- Provider-observed facts used by inventory and preview policy evaluation. Absence remains UNKNOWN.
INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('data.source_type','1.0.0','STRING','Provider-reported AI data-source type.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_acl_enforced','1.0.0','BOOLEAN','Provider-reported data-source ACL enforcement state.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_public_content_access','1.0.0','BOOLEAN','Provider-reported public content-access state for an AI data source or store.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_sensitivity','1.0.0','STRING','Authoritative sensitivity state; missing or failed classification remains UNKNOWN.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.sensitivity_source','1.0.0','STRING','Authoritative sensitivity-classification provider.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.retrieval_mode','1.0.0','STRING','Provider-reported retrieval mode.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.inbound_auth_type','1.0.0','STRING','Provider-reported inbound gateway authorization type.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.outbound_auth_type','1.0.0','STRING','Provider-reported target credential-provider type without credentials.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.private_endpoint','1.0.0','BOOLEAN','Provider-reported private endpoint presence for MCP configuration.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.last_synchronized_at','1.0.0','STRING','Provider-reported last successful MCP target synchronization time.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400)
ON CONFLICT DO NOTHING;


-- source: V74__retire_legacy_ai_policy_distribution.sql
-- V67 only backfilled this table for staged compatibility.  AI Grid has been
-- authoritative for all runtime reads and writes since the consolidation.
DROP TABLE IF EXISTS platform.ai_security_policy_distribution;


-- source: V75__ai_grid_phase_1_catalog_contract.sql
CREATE TABLE platform.ai_grid_control_objectives (
    control_objective_id varchar(128) PRIMARY KEY,
    name varchar(512) NOT NULL,
    security_intent text NOT NULL,
    remediation_intent text NOT NULL,
    owner varchar(255) NOT NULL,
    lifecycle varchar(32) NOT NULL CHECK (lifecycle IN ('DRAFT','ACTIVE','RETIRED')),
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS control_objective_id varchar(128) REFERENCES platform.ai_grid_control_objectives(control_objective_id),
    ADD COLUMN IF NOT EXISTS provider varchar(32),
    ADD COLUMN IF NOT EXISTS evaluation_mode varchar(32),
    ADD COLUMN IF NOT EXISTS evaluation_definition_json jsonb,
    ADD COLUMN IF NOT EXISTS base_evidence_tiers_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS conditional_capabilities_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS certification_parameter_profile_json jsonb;

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_provider_check CHECK (provider IS NULL OR provider IN ('AWS','AZURE','MULTI_CLOUD')),
    ADD CONSTRAINT ai_grid_policy_evaluation_mode_check CHECK (evaluation_mode IS NULL OR evaluation_mode IN ('ARTIFACT_FACTS','DIRECT_RELATIONSHIP','CORRELATION_PATH'));

CREATE TABLE platform.ai_grid_capability_definitions (
    capability_id varchar(128) PRIMARY KEY,
    provider varchar(32) NOT NULL CHECK (provider IN ('AWS','AZURE','MULTI_CLOUD')),
    connector varchar(128) NOT NULL,
    resource_family varchar(128) NOT NULL,
    optional boolean NOT NULL DEFAULT false,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','RETIRED')),
    remediation text NOT NULL
);

INSERT INTO platform.ai_grid_capability_definitions
    (capability_id,provider,connector,resource_family,optional,remediation)
VALUES
    ('BEDROCK_AGENTS','AWS','AWS_DISCOVERY','BEDROCK_AGENTS',false,'Grant the read-only Bedrock Agents permissions and run discovery.'),
    ('BEDROCK_GUARDRAILS','AWS','AWS_DISCOVERY','BEDROCK_GUARDRAILS',false,'Grant the read-only Bedrock Guardrails permissions and run discovery.'),
    ('BEDROCK_KNOWLEDGE_BASES','AWS','AWS_DISCOVERY','BEDROCK_KNOWLEDGE_BASES',false,'Grant the read-only Bedrock Knowledge Bases permissions and run discovery.'),
    ('BEDROCK_MODELS_JOBS','AWS','AWS_DISCOVERY','BEDROCK_MODELS_AND_JOBS',false,'Grant the read-only Bedrock models and jobs permissions and run discovery.'),
    ('BEDROCK_INVOCATION_LOGGING','AWS','AWS_DISCOVERY','BEDROCK_INVOCATION_LOGGING',false,'Grant the read-only Bedrock logging permissions and run discovery.'),
    ('IAM_ROLE_POLICIES','AWS','AWS_DISCOVERY','IAM_ROLE_POLICIES',false,'Grant the read-only IAM role-policy permissions and run discovery.'),
    ('LAMBDA_URLS','AWS','AWS_DISCOVERY','LAMBDA_URLS',false,'Grant the read-only Lambda URL permissions and run discovery.'),
    ('AGENTCORE_GATEWAYS_TARGETS','AWS','AWS_DISCOVERY','AGENTCORE_GATEWAYS_AND_TARGETS',false,'Grant the read-only AgentCore gateway and target permissions and run discovery.'),
    ('SAGEMAKER_DOMAINS_MODELS_ENDPOINTS','AWS','AWS_DISCOVERY','SAGEMAKER_DOMAINS_MODELS_ENDPOINTS',false,'Grant the read-only SageMaker permissions and run discovery.'),
    ('MACIE_CLASSIFICATION','AWS','AWS_MACIE','MACIE_CLASSIFICATION',true,'Enable the read-only Macie classification integration for the applicable account.'),
    ('AI_ACCOUNTS','AZURE','AZURE_DISCOVERY','AI_ACCOUNTS',false,'Grant the read-only Azure AI Account permissions and run discovery.'),
    ('DIAGNOSTIC_SETTINGS','AZURE','AZURE_DISCOVERY','DIAGNOSTIC_SETTINGS',false,'Grant the read-only diagnostic settings permissions and run discovery.'),
    ('FOUNDRY_DEPLOYMENTS_RAI','AZURE','AZURE_DISCOVERY','FOUNDRY_DEPLOYMENTS_AND_RAI',false,'Grant the read-only Foundry deployment and RAI permissions and run discovery.'),
    ('FOUNDRY_AGENTS_TOOLS','AZURE','AZURE_DISCOVERY','FOUNDRY_AGENTS_AND_TOOLS',true,'Enable the read-only Foundry agent and tool metadata collection.'),
    ('ML_WORKSPACES_ENDPOINTS','AZURE','AZURE_DISCOVERY','ML_WORKSPACES_AND_ENDPOINTS',false,'Grant the read-only Azure ML workspace and endpoint permissions and run discovery.'),
    ('SEARCH_CONTROL_PLANE','AZURE','AZURE_DISCOVERY','SEARCH_CONTROL_PLANE',false,'Grant the read-only Azure AI Search control-plane permissions and run discovery.'),
    ('BOT_CONFIGURATION','AZURE','AZURE_DISCOVERY','BOT_CONFIGURATION',false,'Grant the read-only Azure Bot configuration permissions and run discovery.'),
    ('RBAC_ASSIGNMENTS','AZURE','AZURE_DISCOVERY','RBAC_ASSIGNMENTS',false,'Grant the read-only Azure RBAC assignment permissions and run discovery.'),
    ('PURVIEW_CLASSIFICATION','AZURE','AZURE_PURVIEW','PURVIEW_CLASSIFICATION',true,'Enable the read-only Purview classification integration for the applicable subscription.'),
    ('FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE','AZURE','AZURE_DISCOVERY','FOUNDRY_AGENTS_SEARCH_DATA_PLANE',true,'Enable the required read-only Foundry Agents or Search data-plane metadata collection.'),
    ('MULTI_CLOUD_GRAPH','MULTI_CLOUD','AI_GRID_GRAPH','DIRECT_RELATIONSHIPS',false,'Collect complete, fresh direct relationship evidence for the coverage epoch.')
ON CONFLICT (capability_id) DO NOTHING;

UPDATE platform.tenant_schema_versions
   SET target_version = 66,
       status = CASE WHEN current_version < 66 THEN 'PENDING' ELSE status END,
       updated_at = now()
 WHERE target_version < 66;
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 66;


-- source: V76__seed_ai_grid_phase_1_catalog.sql
-- Generated by scripts/compile-ai-grid-phase1.mjs. Do not hand-edit package rows.

INSERT INTO platform.ai_grid_control_objectives
    (control_objective_id,name,security_intent,remediation_intent,owner,lifecycle)
VALUES
('AGCF-OBJ-AWS-001','Bedrock agent has no guardrail attached','Prevent the risk condition described by AGCF-AWS-001.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-002','Attached Bedrock guardrail is below the configured minimum strength','Prevent the risk condition described by AGCF-AWS-002.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-003','Bedrock agent is not in an approved operational state','Prevent the risk condition described by AGCF-AWS-003.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-004','Bedrock agent execution role is missing','Prevent the risk condition described by AGCF-AWS-004.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-005','Bedrock execution role contains wildcard actions','Prevent the risk condition described by AGCF-AWS-005.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-006','Action-group Lambda URL permits unauthenticated invocation','Prevent the risk condition described by AGCF-AWS-006.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-007','Agent foundation model is outside the tenant-approved allowlist','Prevent the risk condition described by AGCF-AWS-007.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-008','Agent action-group Lambda target is outside the approved target allowlist','Prevent the risk condition described by AGCF-AWS-008.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-009','Bedrock model invocation logging is disabled','Prevent the risk condition described by AGCF-AWS-009.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-010','Bedrock guardrail is failed, deleting, or otherwise non-active','Prevent the risk condition described by AGCF-AWS-010.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-011','Bedrock guardrail lacks a customer-managed KMS key where CMK is required','Prevent the risk condition described by AGCF-AWS-011.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-012','Bedrock guardrail has no configured content filters','Prevent the risk condition described by AGCF-AWS-012.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-013','Sensitive-data agent lacks configured PII guardrail entities','Prevent the risk condition described by AGCF-AWS-013.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-014','Grounded-generation baseline requires contextual grounding filters, but none are configured','Prevent the risk condition described by AGCF-AWS-014.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-015','Denied-topic baseline is required, but no denied topics are configured','Prevent the risk condition described by AGCF-AWS-015.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-016','Guardrail configuration has not been reviewed within the configured maximum age','Prevent the risk condition described by AGCF-AWS-016.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-017','Bedrock knowledge base uses an S3 source with public policy exposure','Prevent the risk condition described by AGCF-AWS-017.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-018','Bedrock knowledge base is failed or unavailable','Prevent the risk condition described by AGCF-AWS-018.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-019','Bedrock data source is failed or unavailable','Prevent the risk condition described by AGCF-AWS-019.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-020','Bedrock data-source configuration is absent','Prevent the risk condition described by AGCF-AWS-020.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-021','Bedrock data-source type is outside the approved source allowlist','Prevent the risk condition described by AGCF-AWS-021.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-022','Bedrock data deletion policy violates the tenant retention baseline','Prevent the risk condition described by AGCF-AWS-022.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-023','AI data store has unknown, failed, or stale sensitivity classification','Prevent the risk condition described by AGCF-AWS-023.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-024','Macie-confirmed sensitive AI data store permits public content access','Prevent the risk condition described by AGCF-AWS-024.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-025','Bedrock custom model lacks a customer-managed KMS key where required','Prevent the risk condition described by AGCF-AWS-025.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-026','Bedrock imported model lacks a customer-managed KMS key where required','Prevent the risk condition described by AGCF-AWS-026.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-027','Referenced foundation model lifecycle is not ACTIVE','Prevent the risk condition described by AGCF-AWS-027.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-028','Model provider or model identifier is outside the approved allowlist','Prevent the risk condition described by AGCF-AWS-028.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-029','Bedrock custom/imported model or customization job is in a failed terminal state','Prevent the risk condition described by AGCF-AWS-029.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-030','Provisioned model or inference profile is in an unhealthy state','Prevent the risk condition described by AGCF-AWS-030.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-031','AgentCore gateway inbound authorization is missing or outside the approved auth types','Prevent the risk condition described by AGCF-AWS-031.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-032','AgentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types','Prevent the risk condition described by AGCF-AWS-032.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-033','AgentCore target is failed, unsynchronized, or stale beyond the configured age','Prevent the risk condition described by AGCF-AWS-033.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-034','MCP target subtype or server hostname is outside the tenant allowlist','Prevent the risk condition described by AGCF-AWS-034.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-035','SageMaker domain lacks VPC attachment','Prevent the risk condition described by AGCF-AWS-035.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-036','SageMaker endpoint, model package, or execution space is in a failed terminal state','Prevent the risk condition described by AGCF-AWS-036.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-037','SageMaker notebook instance type is outside the approved compute baseline','Prevent the risk condition described by AGCF-AWS-037.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AWS-038','Bedrock flow is failed or outside the approved lifecycle state','Prevent the risk condition described by AGCF-AWS-038.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-001','Azure AI, ML workspace, or Search service permits unrestricted public network access','Prevent the risk condition described by AGCF-AZR-001.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-002','Private endpoint is absent where the tenant baseline requires one','Prevent the risk condition described by AGCF-AZR-002.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-003','Azure AI account permits local/key authentication','Prevent the risk condition described by AGCF-AZR-003.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-004','Azure AI account lacks customer-managed-key encryption where required','Prevent the risk condition described by AGCF-AZR-004.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-005','Azure AI diagnostic logging is disabled','Prevent the risk condition described by AGCF-AZR-005.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-006','Diagnostic settings have no enabled destination','Prevent the risk condition described by AGCF-AZR-006.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-007','Managed AI resource provisioning state is failed or non-succeeded','Prevent the risk condition described by AGCF-AZR-007.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-008','Managed AI resource lacks a confirmed owner tag','Prevent the risk condition described by AGCF-AZR-008.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-009','Managed AI resource lacks required environment or criticality tags','Prevent the risk condition described by AGCF-AZR-009.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-010','Azure RAI policy explicitly disables or does not block a returned filter','Prevent the risk condition described by AGCF-AZR-010.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-011','Azure RAI policy has no content-filter definitions','Prevent the risk condition described by AGCF-AZR-011.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-012','Foundry deployment has no RAI policy reference','Prevent the risk condition described by AGCF-AZR-012.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-013','RAI mode or base policy is outside the approved baseline','Prevent the risk condition described by AGCF-AZR-013.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-014','Required custom blocklist baseline is absent','Prevent the risk condition described by AGCF-AZR-014.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-015','Foundry model name or publisher is outside the approved allowlist','Prevent the risk condition described by AGCF-AZR-015.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-016','Foundry model version or upgrade option violates the patch/lifecycle baseline','Prevent the risk condition described by AGCF-AZR-016.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-017','Foundry agent has Code Interpreter enabled outside an approved scope','Prevent the risk condition described by AGCF-AZR-017.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-018','Foundry agent model deployment is absent or outside the approved allowlist','Prevent the risk condition described by AGCF-AZR-018.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-019','Foundry MCP server uses NONE or UNKNOWN configured authentication','Prevent the risk condition described by AGCF-AZR-019.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-020','Foundry MCP server hostname is outside the approved allowlist','Prevent the risk condition described by AGCF-AZR-020.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-021','Foundry agent uses a tool type outside the approved tool allowlist','Prevent the risk condition described by AGCF-AZR-021.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-022','Azure ML online endpoint permits local/key authentication','Prevent the risk condition described by AGCF-AZR-022.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-023','Azure ML endpoint traffic references a missing or non-ready deployment','Prevent the risk condition described by AGCF-AZR-023.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-024','Azure ML deployment instance type or model reference is outside the approved baseline','Prevent the risk condition described by AGCF-AZR-024.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-025','Azure ML job or pipeline is in a failed terminal state','Prevent the risk condition described by AGCF-AZR-025.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-026','Azure AI Search permits local admin-key authentication','Prevent the risk condition described by AGCF-AZR-026.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-027','Azure Bot uses password authentication without managed identity','Prevent the risk condition described by AGCF-AZR-027.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-028','Azure Bot has no managed identity where the baseline requires one','Prevent the risk condition described by AGCF-AZR-028.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-029','Azure Bot channel is outside the approved channel allowlist','Prevent the risk condition described by AGCF-AZR-029.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-030','High-privilege Azure role assignment is broader than the approved AI resource scope','Prevent the risk condition described by AGCF-AZR-030.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-031','High-privilege Azure role assignment lacks the required condition or approved principal type','Prevent the risk condition described by AGCF-AZR-031.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-AZR-032','AI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification','Prevent the risk condition described by AGCF-AZR-032.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-001','Publicly reachable AI service has a direct path to confirmed sensitive data','Prevent the risk condition described by AGCF-XSP-001.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-002','Code Interpreter or another high-impact tool has a direct path to confirmed sensitive data','Prevent the risk condition described by AGCF-XSP-002.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-003','Wildcard or broad identity permissions reach a high-impact agent tool','Prevent the risk condition described by AGCF-XSP-003.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-004','External or unapproved MCP server is reachable from an agent that can access sensitive data','Prevent the risk condition described by AGCF-XSP-004.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-005','Agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth','Prevent the risk condition described by AGCF-XSP-005.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE'),
('AGCF-OBJ-XSP-006','Agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline','Prevent the risk condition described by AGCF-XSP-006.','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','AI Grid Security','ACTIVE')
ON CONFLICT (control_objective_id) DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('bedrock.agent.guardrail_attached_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-001.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('bedrock.guardrail.minimum_strength_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-002.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agent.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-003.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.execution_role_present_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-004.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.wildcard_permission_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-005.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('compute.lambda_url_auth_type_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-006.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-007.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-007.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-008.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-008.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('logging.model_invocation_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-009.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-010.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-011.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-011.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('guardrail.content_filter_count_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-012.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-013.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-013.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-014.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-014.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-015.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-015.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-016.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-016.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-017.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-017.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-018.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-019.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('data.source_count_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-020.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-021.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-021.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-022.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-022.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-023.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-023.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-024.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-024.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-025.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-025.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-026.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-026.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-027.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-028.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-028.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-029.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-030.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('mcp.inbound_auth_type','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-031.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('mcp.outbound_auth_type','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-032.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('mcp.target_status','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-033.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-034.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-034.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-035.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-035.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-036.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-aws-037.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-037.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AWS-038.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('network.public_access_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-001.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('network.private_endpoint_count_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-002.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.local_auth_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-003.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('data.customer_managed_key_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-004.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('logging.diagnostic_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-005.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('logging.diagnostic_destination_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-006.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.provisioning_state_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-007.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('owner.owner_tag_present_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-008.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-009.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-009.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('guardrail.rai_non_blocking_filter_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-010.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('guardrail.rai_filter_count_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-011.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('guardrail.rai_policy_reference_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-012.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-013.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-013.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-014.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-014.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-015.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-015.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-016.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-016.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agent.code_interpreter_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-017.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agent.model_deployment_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-018.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('mcp.configured_auth_type','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-019.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-020.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-020.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-021.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-021.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.ml_endpoint_local_auth_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-022.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-023.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-023.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-024.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-024.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('resource.status_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-025.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.search_local_admin_auth_enabled_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-026.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.bot_password_without_managed_identity_observed','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-027.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('identity.managed_identity_assigned_configured','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-028.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-029.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-029.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-030.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-030.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-031.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-031.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-azr-032.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-AZR-032.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-001.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-001.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-002.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-002.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-003.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-003.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-004.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-004.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-005.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-005.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400),
('agcf.agcf-xsp-006.evidence','1.0.0','BOOLEAN','Phase 1 evidence for AGCF-XSP-006.','["CONFIGURATION","GRAPH_ANALYSIS"]','["POSTURE_FINDING","VALIDATED_EXPOSURE"]',86400)
ON CONFLICT (fact_key,version) DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions
    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,artifact_types_json,native_kinds_json,required_capabilities_json,required_relationships_json,required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation,framework_mappings_json,parameter_definitions_json,package_digest,package_source_ref,authored_by,control_objective_id,provider,evaluation_mode,evaluation_definition_json,base_evidence_tiers_json,conditional_capabilities_json,certification_parameter_profile_json,scope_resolution,approved_by,approved_at,published_at)
VALUES
('AGCF-AWS-001','1.0.0','Bedrock agent has no guardrail attached','Detects when bedrock agent has no guardrail attached using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"bedrock.agent.guardrail_attached_configured","eq":false}','AGCF_AGCF_AWS_001','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','bb90c00dc128affac5b962d766e1960cc5a2f301541447184566a060869299ad','policy-packages/agcf/AGCF-AWS-001/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-001','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"bedrock.agent.guardrail_attached_configured","eq":false}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-002','1.0.0','Attached Bedrock guardrail is below the configured minimum strength','Detects when attached Bedrock guardrail is below the configured minimum strength using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"bedrock.guardrail.minimum_strength_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"bedrock.guardrail.minimum_strength_configured","strength_lt":"HIGH"}','AGCF_AGCF_AWS_002','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','5fc4b57091bc8034251cba20c593af5ba12fa7e491a7557bb22f53216cf7b499','policy-packages/agcf/AGCF-AWS-002/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-002','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"bedrock.guardrail.minimum_strength_configured","strength_lt":"HIGH"}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-003','1.0.0','Bedrock agent is not in an approved operational state','Detects when bedrock agent is not in an approved operational state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"agent.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"agent.status_observed","in":["FAILED","DELETING","PREPARE_FAILED"]}','AGCF_AGCF_AWS_003','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"INFORMATIVE","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','326221dc99da9e3f3ac79c4de242329dcd9d8ab44ddd0fbf14a5640e629a7064','policy-packages/agcf/AGCF-AWS-003/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-003','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agent.status_observed","in":["FAILED","DELETING","PREPARE_FAILED"]}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-004','1.0.0','Bedrock agent execution role is missing','Detects when bedrock agent execution role is missing using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["BEDROCK_AGENTS","IAM_ROLE_POLICIES"]','[]','[]','[{"factKey":"identity.execution_role_present_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.execution_role_present_configured","eq":false}','AGCF_AGCF_AWS_004','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','b054cbf59eefac6278dc9ddcf5c8f7ea4e79dbac0a0ce7b7b21481b3cacdec77','policy-packages/agcf/AGCF-AWS-004/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-004','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.execution_role_present_configured","eq":false}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-005','1.0.0','Bedrock execution role contains wildcard actions','Detects when bedrock execution role contains wildcard actions using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["BEDROCK_AGENTS","IAM_ROLE_POLICIES"]','[]','[]','[{"factKey":"identity.wildcard_permission_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.wildcard_permission_observed","eq":true}','AGCF_AGCF_AWS_005','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-05","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','3f997745b4714d233122ed63b8555dd16159a7b7b0b18ab50029728718029699','policy-packages/agcf/AGCF-AWS-005/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-005','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.wildcard_permission_observed","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-006','1.0.0','Action-group Lambda URL permits unauthenticated invocation','Detects when action-group Lambda URL permits unauthenticated invocation using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["LAMBDA_URLS"]','[]','[]','[{"factKey":"compute.lambda_url_auth_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"compute.lambda_url_auth_type_configured","eq":"NONE"}','AGCF_AGCF_AWS_006','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-15","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-08","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','85160e334c349b2e050f40f56a4938a8c791c2626c5f0038106f4d0666fccaa8','policy-packages/agcf/AGCF-AWS-006/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-006','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"compute.lambda_url_auth_type_configured","eq":"NONE"}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-007','1.0.0','Agent foundation model is outside the tenant-approved allowlist','Detects when agent foundation model is outside the tenant-approved allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"agcf.agcf-aws-007.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-007.evidence","eq":true}','AGCF_AGCF_AWS_007','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-12","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','d78027413aeb9168042ba7e79eae2e7c090e7dcecbb82d5ed9400f691ee26c51','policy-packages/agcf/AGCF-AWS-007/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-007','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-007.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-008','1.0.0','Agent action-group Lambda target is outside the approved target allowlist','Detects when agent action-group Lambda target is outside the approved target allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["LAMBDA_URLS"]','["DIRECT_PROVIDER_RELATIONSHIP"]','[]','[{"factKey":"agcf.agcf-aws-008.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-008.evidence","eq":true}','AGCF_AGCF_AWS_008','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','b864fb9d53e7145de8610d2e69c0252d412f0c445990b56262cf13f610049032','policy-packages/agcf/AGCF-AWS-008/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-008','AWS','DIRECT_RELATIONSHIP','{"mode":"DIRECT_RELATIONSHIP","directRelationship":{"sourcePredicate":{"fact":"agcf.agcf-aws-008.evidence","eq":true},"edgeConstraints":["DIRECT_PROVIDER_RELATIONSHIP"],"targetPredicate":{"fact":"agcf.agcf-aws-008.evidence","eq":true},"targetCardinality":"ONE_OR_MORE"}}','["E2"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-009','1.0.0','Bedrock model invocation logging is disabled','Detects when bedrock model invocation logging is disabled using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"logging.model_invocation_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"logging.model_invocation_enabled_configured","eq":false}','AGCF_AGCF_AWS_009','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-07","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-15","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-16","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','5bca40fff893c157d7116ddede6774486c263a1ced7f7241674cacb2dcfeb2cf','policy-packages/agcf/AGCF-AWS-009/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-009','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"logging.model_invocation_enabled_configured","eq":false}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-010','1.0.0','Bedrock guardrail is failed, deleting, or otherwise non-active','Detects when bedrock guardrail is failed, deleting, or otherwise non-active using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","DELETING","INACTIVE"]}','AGCF_AGCF_AWS_010','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','376cd60c4e6bd5c005ad5c04c527f87a793504b56be62ba4fdcf8860039a2d90','policy-packages/agcf/AGCF-AWS-010/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-010','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","DELETING","INACTIVE"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-011','1.0.0','Bedrock guardrail lacks a customer-managed KMS key where CMK is required','Detects when bedrock guardrail lacks a customer-managed KMS key where CMK is required using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"agcf.agcf-aws-011.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-011.evidence","eq":true}','AGCF_AGCF_AWS_011','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','7acc70d799eb1a6fe951c773e66788b4928f9d56b91f625eb80df87f7a083042','policy-packages/agcf/AGCF-AWS-011/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-011','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-011.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-012','1.0.0','Bedrock guardrail has no configured content filters','Detects when bedrock guardrail has no configured content filters using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"guardrail.content_filter_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.content_filter_count_configured","count_eq":0}','AGCF_AGCF_AWS_012','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','de26f82e634c3a3d95b3a184abb7c5cac22c8703eb8a27f012094926f5c690ed','policy-packages/agcf/AGCF-AWS-012/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-012','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.content_filter_count_configured","count_eq":0}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-013','1.0.0','Sensitive-data agent lacks configured PII guardrail entities','Detects when sensitive-data agent lacks configured PII guardrail entities using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','["AI_ARTIFACT"]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"agcf.agcf-aws-013.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-013.evidence","eq":true}','AGCF_AGCF_AWS_013','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','1ab20d9ab9cb8de7353c51878e8a110221f113ac969bf26c4f51e15f1469eede','policy-packages/agcf/AGCF-AWS-013/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-013','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-013.evidence","eq":true}}}','["E1"]','["MACIE_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-AWS-014','1.0.0','Grounded-generation baseline requires contextual grounding filters, but none are configured','Detects when grounded-generation baseline requires contextual grounding filters, but none are configured using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-014.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-014.evidence","eq":true}','AGCF_AGCF_AWS_014','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM07","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-13","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','da1209c9dcbebc0cfbbc9f602b0835c42a3f2956ecb3126bea1c602567081c41','policy-packages/agcf/AGCF-AWS-014/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-014','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-014.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-015','1.0.0','Denied-topic baseline is required, but no denied topics are configured','Detects when denied-topic baseline is required, but no denied topics are configured using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-015.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-015.evidence","eq":true}','AGCF_AGCF_AWS_015','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM07","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','d035679dedaa24e0fd3852fbbdc2311bbffa37b868c44227f0ef56aa0f32db55','policy-packages/agcf/AGCF-AWS-015/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-015','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-015.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-016','1.0.0','Guardrail configuration has not been reviewed within the configured maximum age','Detects when guardrail configuration has not been reviewed within the configured maximum age using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_GUARDRAILS"]','[]','[]','[{"factKey":"agcf.agcf-aws-016.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-016.evidence","eq":true}','AGCF_AGCF_AWS_016','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"INFORMATIVE","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CCC-06","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','6b4bb38ae7ac75a0228147b871e65b868b501f4024712589a0f501d648bceb4e','policy-packages/agcf/AGCF-AWS-016/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-016','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-016.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-017','1.0.0','Bedrock knowledge base uses an S3 source with public policy exposure','Detects when bedrock knowledge base uses an S3 source with public policy exposure using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','["AI_ARTIFACT"]','[]','["BEDROCK_KNOWLEDGE_BASES"]','[]','[]','[{"factKey":"agcf.agcf-aws-017.evidence","valueType":"BOOLEAN","evidenceClasses":["E0"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-017.evidence","eq":true}','AGCF_AGCF_AWS_017','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-16","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','20517c4199a20eb8f25996aa83b5267039ea172458e972d127e5b3001e32e689','policy-packages/agcf/AGCF-AWS-017/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-017','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-017.evidence","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-018','1.0.0','Bedrock knowledge base is failed or unavailable','Detects when bedrock knowledge base is failed or unavailable using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_KNOWLEDGE_BASES"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","DELETE_UNSUCCESSFUL","UNAVAILABLE"]}','AGCF_AGCF_AWS_018','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"INFORMATIVE","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"BCR-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','549bb54d7ab9c99e749ee69abac683d7932658116ecf4c88a0b90c5ab0011f23','policy-packages/agcf/AGCF-AWS-018/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-018','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","DELETE_UNSUCCESSFUL","UNAVAILABLE"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-019','1.0.0','Bedrock data source is failed or unavailable','Detects when bedrock data source is failed or unavailable using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_KNOWLEDGE_BASES"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","DELETE_UNSUCCESSFUL","UNAVAILABLE"]}','AGCF_AGCF_AWS_019','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-20","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-23","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','414b2f2ebff3170b318b22fa95981c6a19e84467122bd9857e778fd0aeb2b9b6','policy-packages/agcf/AGCF-AWS-019/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-019','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","DELETE_UNSUCCESSFUL","UNAVAILABLE"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-020','1.0.0','Bedrock data-source configuration is absent','Detects when bedrock data-source configuration is absent using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"data.source_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.source_count_configured","count_eq":0}','AGCF_AGCF_AWS_020','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','a932a6a1b0a346a03845e0d6448ec48d0b9afd9606efa61324b7904bb3539515','policy-packages/agcf/AGCF-AWS-020/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-020','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.source_count_configured","count_eq":0}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-021','1.0.0','Bedrock data-source type is outside the approved source allowlist','Detects when bedrock data-source type is outside the approved source allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-021.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-021.evidence","eq":true}','AGCF_AGCF_AWS_021','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-20","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','ac356e016116436d6bc27ddcf3d6b58bee05e2bd95f3593e3011a98f6fed2ffc','policy-packages/agcf/AGCF-AWS-021/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-021','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-021.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-022','1.0.0','Bedrock data deletion policy violates the tenant retention baseline','Detects when bedrock data deletion policy violates the tenant retention baseline using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-022.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-022.evidence","eq":true}','AGCF_AGCF_AWS_022','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-16","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','9a6f1fd6b13aff589967a9cdfd91bc8c47458cf80bd0f40bcac0894d98a9797f','policy-packages/agcf/AGCF-AWS-022/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-022','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-022.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-023','1.0.0','AI data store has unknown, failed, or stale sensitivity classification','Detects when aI data store has unknown, failed, or stale sensitivity classification using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','["AI_ARTIFACT"]','[]','["BEDROCK_KNOWLEDGE_BASES"]','[]','[]','[{"factKey":"agcf.agcf-aws-023.evidence","valueType":"BOOLEAN","evidenceClasses":["E0"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-023.evidence","eq":true}','AGCF_AGCF_AWS_023','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','0461915a6cb580685d8d541d6d300dafef0f0453a8db704dc97cbb65d3d2f474','policy-packages/agcf/AGCF-AWS-023/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-023','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-023.evidence","eq":true}}}','["E0"]','["MACIE_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-AWS-024','1.0.0','Macie-confirmed sensitive AI data store permits public content access','Detects when macie-confirmed sensitive AI data store permits public content access using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','["AI_ARTIFACT"]','[]','["BEDROCK_KNOWLEDGE_BASES"]','[]','[]','[{"factKey":"agcf.agcf-aws-024.evidence","valueType":"BOOLEAN","evidenceClasses":["E0"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-024.evidence","eq":true}','AGCF_AGCF_AWS_024','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','6bdf57382ae0139ab630f6b4af3ec6f01ea1f5c56d2c04dd78ba4340fa7116c2','policy-packages/agcf/AGCF-AWS-024/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-024','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-024.evidence","eq":true}}}','["E0"]','["MACIE_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-AWS-025','1.0.0','Bedrock custom model lacks a customer-managed KMS key where required','Detects when bedrock custom model lacks a customer-managed KMS key where required using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"agcf.agcf-aws-025.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-025.evidence","eq":true}','AGCF_AGCF_AWS_025','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-08","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','3f6825e2a689d71d9c1f3aa379cc433dc91f1e063cca7d067e518959005f1782','policy-packages/agcf/AGCF-AWS-025/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-025','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-025.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-026','1.0.0','Bedrock imported model lacks a customer-managed KMS key where required','Detects when bedrock imported model lacks a customer-managed KMS key where required using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"agcf.agcf-aws-026.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-026.evidence","eq":true}','AGCF_AGCF_AWS_026','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','7c2990a5141e2f9e1b023278cfcb029b9f0f4d16667201b06d0aea3485ec81a5','policy-packages/agcf/AGCF-AWS-026/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-026','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-026.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-027','1.0.0','Referenced foundation model lifecycle is not ACTIVE','Detects when referenced foundation model lifecycle is not ACTIVE using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["LEGACY","DEPRECATED","RETIRED"]}','AGCF_AGCF_AWS_027','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-10","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-12","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','fa164a410f1083f76903a012987c05354c56fba47194e933e42ab7f02ee44d9e','policy-packages/agcf/AGCF-AWS-027/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-027','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["LEGACY","DEPRECATED","RETIRED"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-028','1.0.0','Model provider or model identifier is outside the approved allowlist','Detects when model provider or model identifier is outside the approved allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"agcf.agcf-aws-028.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-028.evidence","eq":true}','AGCF_AGCF_AWS_028','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-10","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','22fde5d215cafb7730035f77e709f2b0b0d7fc6cb37ba5106fb72936d99bcd7a','policy-packages/agcf/AGCF-AWS-028/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-028','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-028.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-029','1.0.0','Bedrock custom/imported model or customization job is in a failed terminal state','Detects when bedrock custom/imported model or customization job is in a failed terminal state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}','AGCF_AGCF_AWS_029','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','9ed4abbaa6b9125126738e052ca57bc784d2f1d34625f50f6e690d909d4eeb9e','policy-packages/agcf/AGCF-AWS-029/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-029','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-030','1.0.0','Provisioned model or inference profile is in an unhealthy state','Detects when provisioned model or inference profile is in an unhealthy state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_MODELS_JOBS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","STOPPED","UNHEALTHY"]}','AGCF_AGCF_AWS_030','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','f06a49dfdada4264f4ba75abb49a36050179d152dfb3ee91b52d13eece11a756','policy-packages/agcf/AGCF-AWS-030/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-030','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","STOPPED","UNHEALTHY"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-031','1.0.0','AgentCore gateway inbound authorization is missing or outside the approved auth types','Detects when agentCore gateway inbound authorization is missing or outside the approved auth types using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["AGENTCORE_GATEWAYS_TARGETS"]','[]','[]','[{"factKey":"mcp.inbound_auth_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"mcp.inbound_auth_type","in":["NONE","UNKNOWN",""]}','AGCF_AGCF_AWS_031','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-15","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-08","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','1cff186cb30c55959a5d470d6c45699c6f976f0fc23732e4ed8d01b583441a4e','policy-packages/agcf/AGCF-AWS-031/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-031','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"mcp.inbound_auth_type","in":["NONE","UNKNOWN",""]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-032','1.0.0','AgentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types','Detects when agentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["AGENTCORE_GATEWAYS_TARGETS"]','[]','[]','[{"factKey":"mcp.outbound_auth_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"mcp.outbound_auth_type","in":["NONE","UNKNOWN",""]}','AGCF_AGCF_AWS_032','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','21be100bfb41d34bb2cacb5e92116f99495da1a9f1f3602f28bbaa72ea2356ab','policy-packages/agcf/AGCF-AWS-032/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-032','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"mcp.outbound_auth_type","in":["NONE","UNKNOWN",""]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-033','1.0.0','AgentCore target is failed, unsynchronized, or stale beyond the configured age','Detects when agentCore target is failed, unsynchronized, or stale beyond the configured age using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["AGENTCORE_GATEWAYS_TARGETS"]','[]','[]','[{"factKey":"mcp.target_status","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"mcp.target_status","in":["FAILED","UNSYNCHRONIZED"]}','AGCF_AGCF_AWS_033','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-14","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','8dbe375e3bf0b289211501739612954625dd96deca04c0ef3d75ac7472701d69','policy-packages/agcf/AGCF-AWS-033/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-033','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"mcp.target_status","in":["FAILED","UNSYNCHRONIZED"]}}}','["E0","E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-034','1.0.0','MCP target subtype or server hostname is outside the tenant allowlist','Detects when mCP target subtype or server hostname is outside the tenant allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["AGENTCORE_GATEWAYS_TARGETS"]','["DIRECT_PROVIDER_RELATIONSHIP"]','[]','[{"factKey":"agcf.agcf-aws-034.evidence","valueType":"BOOLEAN","evidenceClasses":["E1","E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-034.evidence","eq":true}','AGCF_AGCF_AWS_034','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','fb55a0e003fadb94a87c799a5b4e2d87492526a8e99eb444301e32739705dc36','policy-packages/agcf/AGCF-AWS-034/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-034','AWS','DIRECT_RELATIONSHIP','{"mode":"DIRECT_RELATIONSHIP","directRelationship":{"sourcePredicate":{"fact":"agcf.agcf-aws-034.evidence","eq":true},"edgeConstraints":["DIRECT_PROVIDER_RELATIONSHIP"],"targetPredicate":{"fact":"agcf.agcf-aws-034.evidence","eq":true},"targetCardinality":"ONE_OR_MORE"}}','["E1","E2"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-035','1.0.0','SageMaker domain lacks VPC attachment','Detects when sageMaker domain lacks VPC attachment using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','["AI_ARTIFACT"]','[]','["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-035.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-035.evidence","eq":true}','AGCF_AGCF_AWS_035','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','6a5ffb5b7ea1942fc6b980f05ced1bfeffcdea70912464387f96f0297ed0e2d7','policy-packages/agcf/AGCF-AWS-035/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-035','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-035.evidence","eq":true}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-036','1.0.0','SageMaker endpoint, model package, or execution space is in a failed terminal state','Detects when sageMaker endpoint, model package, or execution space is in a failed terminal state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}','AGCF_AGCF_AWS_036','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"BCR-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','a89526ca507d221d441bbe1eaaddf3235e19d81ecfde801646d910cb2451142b','policy-packages/agcf/AGCF-AWS-036/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-036','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AWS-037','1.0.0','SageMaker notebook instance type is outside the approved compute baseline','Detects when sageMaker notebook instance type is outside the approved compute baseline using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]','[]','[]','[{"factKey":"agcf.agcf-aws-037.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-aws-037.evidence","eq":true}','AGCF_AGCF_AWS_037','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','e502afb51831be2b28bb05c422083602258786d496f48aa4761b8150a05f851e','policy-packages/agcf/AGCF-AWS-037/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-037','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-aws-037.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AWS-038','1.0.0','Bedrock flow is failed or outside the approved lifecycle state','Detects when bedrock flow is failed or outside the approved lifecycle state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BEDROCK_AGENTS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}','AGCF_AGCF_AWS_038','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','9637e391d972c2b6e1c47d21e5c9bf1764c1231c1b001877ff42d8b8309eccf5','policy-packages/agcf/AGCF-AWS-038/1.0.0.json','AI Grid Security','AGCF-OBJ-AWS-038','AWS','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","STOPPED"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-001','1.0.0','Azure AI, ML workspace, or Search service permits unrestricted public network access','Detects when azure AI, ML workspace, or Search service permits unrestricted public network access using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["SEARCH_CONTROL_PLANE"]','[]','[]','[{"factKey":"network.public_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"network.public_access_configured","eq":true}','AGCF_AGCF_AZR_001','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','1ab6c92d300a6c819ca01d0b551490cf53ec6e76adba8fbcc5b4873d3340b697','policy-packages/agcf/AGCF-AZR-001/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-001','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"network.public_access_configured","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-002','1.0.0','Private endpoint is absent where the tenant baseline requires one','Detects when private endpoint is absent where the tenant baseline requires one using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','[]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"network.private_endpoint_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"network.private_endpoint_count_configured","count_eq":0}','AGCF_AGCF_AZR_002','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','912d0e9a6dc8cfbc200ad88ee347603399d0ccc8ea24f41f7c76fc32cf776fb4','policy-packages/agcf/AGCF-AZR-002/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-002','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"network.private_endpoint_count_configured","count_eq":0}}}','["E0"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-003','1.0.0','Azure AI account permits local/key authentication','Detects when azure AI account permits local/key authentication using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"identity.local_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.local_auth_enabled_configured","eq":true}','AGCF_AGCF_AZR_003','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-15","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','0590eb9ba83f35075ab0d9a973648c7cf4975ce8d603548187901964f5973c06','policy-packages/agcf/AGCF-AZR-003/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-003','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.local_auth_enabled_configured","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-004','1.0.0','Azure AI account lacks customer-managed-key encryption where required','Detects when azure AI account lacks customer-managed-key encryption where required using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','[]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"data.customer_managed_key_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.customer_managed_key_configured","eq":false}','AGCF_AGCF_AZR_004','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CEK-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','fe192ff55f0d444b9ee5c5a22c90348f6e16ab1b309d8c25e3b0a4867f796d1b','policy-packages/agcf/AGCF-AZR-004/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-004','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.customer_managed_key_configured","eq":false}}}','["E0"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-005','1.0.0','Azure AI diagnostic logging is disabled','Detects when azure AI diagnostic logging is disabled using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["DIAGNOSTIC_SETTINGS"]','[]','[]','[{"factKey":"logging.diagnostic_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"logging.diagnostic_enabled_configured","eq":false}','AGCF_AGCF_AZR_005','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-03","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-07","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','9d413da2a311da3e8940930c7115cb8df69358996cca1d7e292185dd6e6b924e','policy-packages/agcf/AGCF-AZR-005/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-005','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"logging.diagnostic_enabled_configured","eq":false}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-006','1.0.0','Diagnostic settings have no enabled destination','Detects when diagnostic settings have no enabled destination using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["DIAGNOSTIC_SETTINGS"]','[]','[]','[{"factKey":"logging.diagnostic_destination_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"logging.diagnostic_destination_configured","eq":false}','AGCF_AGCF_AZR_006','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-07","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','9f0d98dc60b3f315e1d660eb80293970caf1dfed75c5ed4b2e88a814964312d3','policy-packages/agcf/AGCF-AZR-006/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-006','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"logging.diagnostic_destination_configured","eq":false}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-007','1.0.0','Managed AI resource provisioning state is failed or non-succeeded','Detects when managed AI resource provisioning state is failed or non-succeeded using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"resource.provisioning_state_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.provisioning_state_observed","in":["FAILED","CANCELED","DELETING"]}','AGCF_AGCF_AZR_007','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"INFORMATIVE","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"LOG-14","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','3fd84e819c631abfd838263ef0b0cf891d8094d2f5b3614392eb7f11a52d62bb','policy-packages/agcf/AGCF-AZR-007/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-007','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.provisioning_state_observed","in":["FAILED","CANCELED","DELETING"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-008','1.0.0','Managed AI resource lacks a confirmed owner tag','Detects when managed AI resource lacks a confirmed owner tag using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"owner.owner_tag_present_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"owner.owner_tag_present_configured","eq":false}','AGCF_AGCF_AZR_008','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DCS-07","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','b4d4c18eb54107d5032e176635e4724096beced4975c6b03c3f6b09ed30535b4','policy-packages/agcf/AGCF-AZR-008/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-008','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"owner.owner_tag_present_configured","eq":false}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-009','1.0.0','Managed AI resource lacks required environment or criticality tags','Detects when managed AI resource lacks required environment or criticality tags using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-009.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-009.evidence","eq":true}','AGCF_AGCF_AZR_009','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DCS-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DCS-07","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','a0cd1adc440bd86f846cf1c76a394f0be08acd0aab4250c0c0a8fe5ce1f66a7a','policy-packages/agcf/AGCF-AZR-009/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-009','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-009.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-010','1.0.0','Azure RAI policy explicitly disables or does not block a returned filter','Detects when azure RAI policy explicitly disables or does not block a returned filter using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["FOUNDRY_DEPLOYMENTS_RAI"]','[]','[]','[{"factKey":"guardrail.rai_non_blocking_filter_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.rai_non_blocking_filter_observed","eq":true}','AGCF_AGCF_AZR_010','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','5b1525a187044529c14a15c277405a1c25abfa1c8f6b4b891ad0160f9cddf442','policy-packages/agcf/AGCF-AZR-010/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-010','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.rai_non_blocking_filter_observed","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-011','1.0.0','Azure RAI policy has no content-filter definitions','Detects when azure RAI policy has no content-filter definitions using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["FOUNDRY_DEPLOYMENTS_RAI"]','[]','[]','[{"factKey":"guardrail.rai_filter_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.rai_filter_count_configured","count_eq":0}','AGCF_AGCF_AZR_011','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','d2b5f3e0b7fad49b91a3ff7e974f9b06089890792fce44d5987dd9007187db78','policy-packages/agcf/AGCF-AZR-011/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-011','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.rai_filter_count_configured","count_eq":0}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-012','1.0.0','Foundry deployment has no RAI policy reference','Detects when foundry deployment has no RAI policy reference using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["FOUNDRY_DEPLOYMENTS_RAI"]','[]','[]','[{"factKey":"guardrail.rai_policy_reference_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.rai_policy_reference_configured","empty":true}','AGCF_AGCF_AZR_012','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CCC-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','0d24ccc33b97f24d58f93ee024033471e2bdc822cfcb6abeb1d8146611e8c7fc','policy-packages/agcf/AGCF-AZR-012/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-012','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.rai_policy_reference_configured","empty":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-013','1.0.0','RAI mode or base policy is outside the approved baseline','Detects when rAI mode or base policy is outside the approved baseline using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["FOUNDRY_DEPLOYMENTS_RAI"]','[]','[]','[{"factKey":"agcf.agcf-azr-013.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-013.evidence","eq":true}','AGCF_AGCF_AZR_013','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CCC-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','4981638b8f11945a9e03008d29be4707cc6600922f31b569d7d95e63d9c7e22c','policy-packages/agcf/AGCF-AZR-013/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-013','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-013.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-014','1.0.0','Required custom blocklist baseline is absent','Detects when required custom blocklist baseline is absent using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-014.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-014.evidence","eq":true}','AGCF_AGCF_AZR_014','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM07","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"GRC-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','857c0dab9b3a2649d0f10db9302be97127d8f3aa43abb14af238a4ff7e829a4f','policy-packages/agcf/AGCF-AZR-014/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-014','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-014.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-015','1.0.0','Foundry model name or publisher is outside the approved allowlist','Detects when foundry model name or publisher is outside the approved allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-015.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-015.evidence","eq":true}','AGCF_AGCF_AZR_015','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-10","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-12","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','3670b13e5f2f3dc23d7da4920b0aa26c4a2cd2477a61f6dda6922ddf0811b57f','policy-packages/agcf/AGCF-AZR-015/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-015','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-015.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-016','1.0.0','Foundry model version or upgrade option violates the patch/lifecycle baseline','Detects when foundry model version or upgrade option violates the patch/lifecycle baseline using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-016.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-016.evidence","eq":true}','AGCF_AGCF_AZR_016','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CCC-06","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','502fedc05ec745bce3a56aeb0c88c50b4a79ed53795932719093be9d25e451b4','policy-packages/agcf/AGCF-AZR-016/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-016','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-016.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-017','1.0.0','Foundry agent has Code Interpreter enabled outside an approved scope','Detects when foundry agent has Code Interpreter enabled outside an approved scope using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','[]','[]','["FOUNDRY_AGENTS_TOOLS"]','[]','[]','[{"factKey":"agent.code_interpreter_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"agent.code_interpreter_enabled_configured","eq":true}','AGCF_AGCF_AZR_017','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','f4f63bd0c5cf9a1e7cb786fc9a284e5fb4f251ce54bf1fac7ca8b59aae870476','policy-packages/agcf/AGCF-AZR-017/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-017','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agent.code_interpreter_enabled_configured","eq":true}}}','["E0"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-018','1.0.0','Foundry agent model deployment is absent or outside the approved allowlist','Detects when foundry agent model deployment is absent or outside the approved allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["FOUNDRY_AGENTS_TOOLS"]','[]','[]','[{"factKey":"agent.model_deployment_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"agent.model_deployment_configured","empty":true}','AGCF_AGCF_AZR_018','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','2aec39fbd18cc999232c311b10da52a067f0532ba63e0ec04e253f9018d275c5','policy-packages/agcf/AGCF-AZR-018/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-018','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agent.model_deployment_configured","empty":true}}}','["E1"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','null','STATIC',null,null,null),
('AGCF-AZR-019','1.0.0','Foundry MCP server uses NONE or UNKNOWN configured authentication','Detects when foundry MCP server uses NONE or UNKNOWN configured authentication using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["FOUNDRY_AGENTS_TOOLS"]','[]','[]','[{"factKey":"mcp.configured_auth_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"mcp.configured_auth_type","in":["NONE","UNKNOWN",""]}','AGCF_AGCF_AZR_019','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','4b7b023c557269b6e58cb5c8b498982b37cdb5936e6a3bac5443f0b79fbd495b','policy-packages/agcf/AGCF-AZR-019/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-019','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"mcp.configured_auth_type","in":["NONE","UNKNOWN",""]}}}','["E0"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','null','STATIC',null,null,null),
('AGCF-AZR-020','1.0.0','Foundry MCP server hostname is outside the approved allowlist','Detects when foundry MCP server hostname is outside the approved allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["FOUNDRY_AGENTS_TOOLS"]','[]','[]','[{"factKey":"agcf.agcf-azr-020.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-020.evidence","eq":true}','AGCF_AGCF_AZR_020','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','763165ea4ab53ca536639e406f98d9f9c5c851e91a6e7df71342fed693f09e70','policy-packages/agcf/AGCF-AZR-020/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-020','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-020.evidence","eq":true}}}','["E1"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-021','1.0.0','Foundry agent uses a tool type outside the approved tool allowlist','Detects when foundry agent uses a tool type outside the approved tool allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["FOUNDRY_AGENTS_TOOLS"]','[]','[]','[{"factKey":"agcf.agcf-azr-021.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-021.evidence","eq":true}','AGCF_AGCF_AZR_021','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','17c942a505b60a14943874c55f6f4572dd1f661a82921ba8592f39444fc8e845','policy-packages/agcf/AGCF-AZR-021/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-021','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-021.evidence","eq":true}}}','["E1"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-022','1.0.0','Azure ML online endpoint permits local/key authentication','Detects when azure ML online endpoint permits local/key authentication using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["ML_WORKSPACES_ENDPOINTS"]','[]','[]','[{"factKey":"identity.ml_endpoint_local_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.ml_endpoint_local_auth_enabled_configured","eq":true}','AGCF_AGCF_AZR_022','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-15","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','9865cdb6de64ce90c5a2768a370cc593b5c76ac23cb1ca89640d500fd9390d55','policy-packages/agcf/AGCF-AZR-022/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-022','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.ml_endpoint_local_auth_enabled_configured","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-023','1.0.0','Azure ML endpoint traffic references a missing or non-ready deployment','Detects when azure ML endpoint traffic references a missing or non-ready deployment using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','["AI_ARTIFACT"]','[]','["ML_WORKSPACES_ENDPOINTS"]','["DIRECT_PROVIDER_RELATIONSHIP"]','[]','[{"factKey":"agcf.agcf-azr-023.evidence","valueType":"BOOLEAN","evidenceClasses":["E1","E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-023.evidence","eq":true}','AGCF_AGCF_AZR_023','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"CCC-06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','399044f9bc57c4355f5e71cda1a36ef2027d9ec5969fcffff6a85027b918bfd7','policy-packages/agcf/AGCF-AZR-023/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-023','AZURE','DIRECT_RELATIONSHIP','{"mode":"DIRECT_RELATIONSHIP","directRelationship":{"sourcePredicate":{"fact":"agcf.agcf-azr-023.evidence","eq":true},"edgeConstraints":["DIRECT_PROVIDER_RELATIONSHIP"],"targetPredicate":{"fact":"agcf.agcf-azr-023.evidence","eq":true},"targetCardinality":"ONE_OR_MORE"}}','["E1","E2"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-024','1.0.0','Azure ML deployment instance type or model reference is outside the approved baseline','Detects when azure ML deployment instance type or model reference is outside the approved baseline using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["ML_WORKSPACES_ENDPOINTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-024.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-024.evidence","eq":true}','AGCF_AGCF_AZR_024','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM06","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','c05e4d7890cd7c6d9df2b2470e618551c81a6e2a8600babae8415f8522b930b3','policy-packages/agcf/AGCF-AZR-024/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-024','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-024.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-025','1.0.0','Azure ML job or pipeline is in a failed terminal state','Detects when azure ML job or pipeline is in a failed terminal state using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["ML_WORKSPACES_ENDPOINTS"]','[]','[]','[{"factKey":"resource.status_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.status_observed","in":["FAILED","CANCELED"]}','AGCF_AGCF_AZR_025','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM05","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-01","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"MDS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','26209af25e6494923ff5e4c232d1405553f2e6aec60b29b1314766ff12af43dd','policy-packages/agcf/AGCF-AZR-025/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-025','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.status_observed","in":["FAILED","CANCELED"]}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-026','1.0.0','Azure AI Search permits local admin-key authentication','Detects when azure AI Search permits local admin-key authentication using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["SEARCH_CONTROL_PLANE"]','[]','[]','[{"factKey":"identity.search_local_admin_auth_enabled_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.search_local_admin_auth_enabled_configured","eq":true}','AGCF_AGCF_AZR_026','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-16","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','926f394fe73ab1814e2eac4d7ec2ed647c0b1449ab7fd3e0b77c3071b6f8f43d','policy-packages/agcf/AGCF-AZR-026/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-026','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.search_local_admin_auth_enabled_configured","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-027','1.0.0','Azure Bot uses password authentication without managed identity','Detects when azure Bot uses password authentication without managed identity using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','[]','[]','["BOT_CONFIGURATION"]','[]','[]','[{"factKey":"identity.bot_password_without_managed_identity_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.bot_password_without_managed_identity_observed","eq":true}','AGCF_AGCF_AZR_027','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','2cce3ece6d9165ea3aa0bfb773a413ec030942ea7c2f6e9d1a5a3c2df532ca35','policy-packages/agcf/AGCF-AZR-027/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-027','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.bot_password_without_managed_identity_observed","eq":true}}}','["E0"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-028','1.0.0','Azure Bot has no managed identity where the baseline requires one','Detects when azure Bot has no managed identity where the baseline requires one using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','[]','[]','["BOT_CONFIGURATION"]','[]','[]','[{"factKey":"identity.managed_identity_assigned_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"identity.managed_identity_assigned_configured","eq":false}','AGCF_AGCF_AZR_028','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','b4a523d319161b425475f3e89714fe0581a16eedde990d53a52bf7ae36c56d39','policy-packages/agcf/AGCF-AZR-028/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-028','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"identity.managed_identity_assigned_configured","eq":false}}}','["E1"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-029','1.0.0','Azure Bot channel is outside the approved channel allowlist','Detects when azure Bot channel is outside the approved channel allowlist using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["BOT_CONFIGURATION"]','[]','[]','[{"factKey":"agcf.agcf-azr-029.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-029.evidence","eq":true}','AGCF_AGCF_AZR_029','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM04","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"STA-08","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','ee6cd123217f9d5f2544c7488b1309d11a8d1919de431e17fb0ce912984c28a9','policy-packages/agcf/AGCF-AZR-029/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-029','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-029.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-030','1.0.0','High-privilege Azure role assignment is broader than the approved AI resource scope','Detects when high-privilege Azure role assignment is broader than the approved AI resource scope using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','REQUIRED','["AI_ARTIFACT"]','[]','["RBAC_ASSIGNMENTS"]','["DIRECT_PROVIDER_RELATIONSHIP"]','[]','[{"factKey":"agcf.agcf-azr-030.evidence","valueType":"BOOLEAN","evidenceClasses":["E1","E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-030.evidence","eq":true}','AGCF_AGCF_AZR_030','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-05","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','fc44729c4749be699010388ba50f62a505c8aeee2215efeb61f5b4492bef9172','policy-packages/agcf/AGCF-AZR-030/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-030','AZURE','DIRECT_RELATIONSHIP','{"mode":"DIRECT_RELATIONSHIP","directRelationship":{"sourcePredicate":{"fact":"agcf.agcf-azr-030.evidence","eq":true},"edgeConstraints":["DIRECT_PROVIDER_RELATIONSHIP"],"targetPredicate":{"fact":"agcf.agcf-azr-030.evidence","eq":true},"targetCardinality":"ONE_OR_MORE"}}','["E1","E2"]','[]','null','STATIC',null,null,null),
('AGCF-AZR-031','1.0.0','High-privilege Azure role assignment lacks the required condition or approved principal type','Detects when high-privilege Azure role assignment lacks the required condition or approved principal type using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','DISABLED','["AI_ARTIFACT"]','[]','["RBAC_ASSIGNMENTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-031.evidence","valueType":"BOOLEAN","evidenceClasses":["E1"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-031.evidence","eq":true}','AGCF_AGCF_AZR_031','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-05","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-10","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-15","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','5ebd79d2f05bec3cfa2b7ac17811ae19de2bbce08e6d86a9ff5559399775a120','policy-packages/agcf/AGCF-AZR-031/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-031','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-031.evidence","eq":true}}}','["E1"]','[]','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','STATIC',null,null,null),
('AGCF-AZR-032','1.0.0','AI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification','Detects when aI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification using only declared evidence.','HIGH','VALIDATED','POSTURE_FINDING','ENABLED','["AI_ARTIFACT"]','[]','["AI_ACCOUNTS"]','[]','[]','[{"factKey":"agcf.agcf-azr-032.evidence","valueType":"BOOLEAN","evidenceClasses":["E0"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-azr-032.evidence","eq":true}','AGCF_AGCF_AZR_032','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-04","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','757f7eeeebf4884c87cb92e76f9ccb3a2a3c8e861929367313356706507e2825','policy-packages/agcf/AGCF-AZR-032/1.0.0.json','AI Grid Security','AGCF-OBJ-AZR-032','AZURE','ARTIFACT_FACTS','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"agcf.agcf-azr-032.evidence","eq":true}}}','["E0"]','["PURVIEW_CLASSIFICATION","FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]','null','STATIC',null,null,null),
('AGCF-XSP-001','1.0.0','Publicly reachable AI service has a direct path to confirmed sensitive data','Detects when publicly reachable AI service has a direct path to confirmed sensitive data using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-001.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-001.evidence","eq":true}','AGCF_AGCF_XSP_001','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"I&S-03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','ea10b34d302b4b9c464624c158653802c26a5d2963373a1ee28e69320a2b7eb2','policy-packages/agcf/AGCF-XSP-001/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-001','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_EXTERNAL_SENSITIVE_ACCESS","correlationVersion":"1.0.0"}}','["E2"]','["MACIE_CLASSIFICATION","PURVIEW_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-XSP-002','1.0.0','Code Interpreter or another high-impact tool has a direct path to confirmed sensitive data','Detects when code Interpreter or another high-impact tool has a direct path to confirmed sensitive data using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-002.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-002.evidence","eq":true}','AGCF_AGCF_XSP_002','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','3ffdc697f7e3567595aba7c1777bda16675e85d4060a88930c80d5767587e85f','policy-packages/agcf/AGCF-XSP-002/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-002','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_UNTRUSTED_AUTONOMOUS_EXECUTION","correlationVersion":"1.0.0"}}','["E2"]','["MACIE_CLASSIFICATION","PURVIEW_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-XSP-003','1.0.0','Wildcard or broad identity permissions reach a high-impact agent tool','Detects when wildcard or broad identity permissions reach a high-impact agent tool using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-003.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-003.evidence","eq":true}','AGCF_AGCF_XSP_003','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-05","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','0bdb736826305b9c09649f3b88638ae74f615e67983953eee4d16d5dd8daca86','policy-packages/agcf/AGCF-XSP-003/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-003','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_EXCESSIVE_TOOL_PRIVILEGE","correlationVersion":"1.0.0"}}','["E2"]','[]','null','STATIC',null,null,null),
('AGCF-XSP-004','1.0.0','External or unapproved MCP server is reachable from an agent that can access sensitive data','Detects when external or unapproved MCP server is reachable from an agent that can access sensitive data using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-004.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-004.evidence","eq":true}','AGCF_AGCF_XSP_004','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','ca3ab5f1338cca9ee966023bae56f082a9c7f7dd4c78ac9c25a2fa22631f11fe','policy-packages/agcf/AGCF-XSP-004/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-004','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_EXTERNAL_MCP_SENSITIVE_ACCESS","correlationVersion":"1.0.0"}}','["E2"]','["MACIE_CLASSIFICATION","PURVIEW_CLASSIFICATION"]','null','STATIC',null,null,null),
('AGCF-XSP-005','1.0.0','Agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth','Detects when agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-005.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-005.evidence","eq":true}','AGCF_AGCF_XSP_005','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM03","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-18","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"AIS-11","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','0e302a440ef10200393a9929cb243aba3451610575dfa575fd736e326e21a1cf','policy-packages/agcf/AGCF-XSP-005/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-005','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_MCP_WEAK_AUTH_EXECUTION","correlationVersion":"1.0.0"}}','["E2"]','[]','null','STATIC',null,null,null),
('AGCF-XSP-006','1.0.0','Agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline','Detects when agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline using only declared evidence.','HIGH','VALIDATED','VALIDATED_EXPOSURE','REQUIRED','["SYSTEM"]','[]','["MULTI_CLOUD_GRAPH"]','[]','[]','[{"factKey":"agcf.agcf-xsp-006.evidence","valueType":"BOOLEAN","evidenceClasses":["E2"],"maxAgeSeconds":86400}]','{"fact":"agcf.agcf-xsp-006.evidence","eq":true}','AGCF_AGCF_XSP_006','Correct the provider configuration or relationship and reassess with complete, fresh evidence.','[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM02","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM09","mappingType":"PARTIAL","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"TVM-13","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"DSP-17","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."},{"framework":"CSA_AICM","frameworkVersion":"1.1","controlId":"IAM-16","mappingType":"DIRECT","rationale":"This control is independently mapped to the policy''s stated security intent."}]','[]','e1a6c5f095a9be0359a84139d689167d1a1606ad09c4cd9a4bc0eb53f2269c66','policy-packages/agcf/AGCF-XSP-006/1.0.0.json','AI Grid Security','AGCF-OBJ-XSP-006','MULTI_CLOUD','CORRELATION_PATH','{"mode":"CORRELATION_PATH","correlationPath":{"correlationId":"R2_SENSITIVE_RETRIEVAL_CONTROL_GAP","correlationVersion":"1.0.0"}}','["E2"]','["MACIE_CLASSIFICATION","PURVIEW_CLASSIFICATION"]','null','STATIC',null,null,null)
  -- generated rows are immutable package versions
ON CONFLICT (policy_id,version) DO NOTHING;

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id,available,default_selection,rollout_stage,updated_by)
VALUES
('AGCF-AWS-001',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-002',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-003',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-004',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-005',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-006',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-007',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-008',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-009',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-010',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-011',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-012',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-013',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-014',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-015',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-016',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-017',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-018',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-019',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-020',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-021',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-022',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-023',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-024',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-025',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-026',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-027',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-028',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-029',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-030',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-031',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-032',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-033',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-034',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-035',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-036',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-037',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AWS-038',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-001',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-002',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-003',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-004',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-005',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-006',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-007',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-008',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-009',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-010',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-011',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-012',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-013',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-014',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-015',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-016',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-017',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-018',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-019',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-020',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-021',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-022',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-023',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-024',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-025',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-026',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-027',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-028',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-029',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-030',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-031',false,'DISABLED','PAUSED','ai-grid-phase-1'),
('AGCF-AZR-032',false,'ENABLED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-001',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-002',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-003',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-004',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-005',false,'REQUIRED','PAUSED','ai-grid-phase-1'),
('AGCF-XSP-006',false,'REQUIRED','PAUSED','ai-grid-phase-1')
ON CONFLICT (policy_id) DO UPDATE SET available=excluded.available,default_selection=excluded.default_selection,rollout_stage=excluded.rollout_stage,updated_by=excluded.updated_by,updated_at=now();

UPDATE platform.ai_grid_policy_distribution SET available=false,rollout_stage='RETIRED',updated_by='ai-grid-phase-1-migration',updated_at=now() WHERE policy_id NOT LIKE 'AGCF-%';
UPDATE platform.ai_grid_policy_versions SET lifecycle='RETIRED' WHERE policy_id NOT LIKE 'AGCF-%' AND lifecycle='PUBLISHED';


-- source: V77__ai_grid_resource_and_relationship_catalog.sql
CREATE TABLE platform.ai_grid_resource_family_definitions (
    resource_family varchar(128) PRIMARY KEY,
    provider varchar(32) NOT NULL CHECK (provider IN ('AWS','AZURE','MULTI_CLOUD')),
    scope_semantics varchar(32) NOT NULL CHECK (scope_semantics IN ('REGIONAL','ACCOUNT_GLOBAL')),
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','RETIRED')),
    description text NOT NULL
);

CREATE TABLE platform.ai_grid_relationship_definitions (
    relationship_type varchar(128) PRIMARY KEY,
    source varchar(64) NOT NULL,
    directional boolean NOT NULL DEFAULT true,
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','RETIRED')),
    description text NOT NULL
);

INSERT INTO platform.ai_grid_resource_family_definitions
    (resource_family,provider,scope_semantics,description)
VALUES
 ('BEDROCK_AGENTS','AWS','REGIONAL','Bedrock Agents discovery.'),
 ('BEDROCK_KNOWLEDGE_BASES','AWS','REGIONAL','Bedrock knowledge base discovery.'),
 ('BEDROCK_DATA_SOURCES','AWS','REGIONAL','Bedrock data-source discovery.'),
 ('BEDROCK_DATA_STORES','AWS','REGIONAL','Bedrock data-store discovery.'),
 ('AWS_AGENTCORE_GATEWAYS','AWS','REGIONAL','AgentCore gateway discovery.'),
 ('AWS_AGENTCORE_GATEWAY_TARGETS','AWS','REGIONAL','AgentCore target discovery.'),
 ('BEDROCK_GUARDRAILS','AWS','REGIONAL','Bedrock Guardrails discovery.'),
 ('BEDROCK_INVOCATION_LOGGING','AWS','REGIONAL','Bedrock invocation logging discovery.'),
 ('BEDROCK_DEPLOYABLE_MODELS','AWS','REGIONAL','Bedrock model discovery.'),
 ('BEDROCK_INFERENCE_PROFILES','AWS','REGIONAL','Bedrock inference-profile discovery.'),
 ('BEDROCK_MODEL_CUSTOMIZATION_JOBS','AWS','REGIONAL','Bedrock customization-job discovery.'),
 ('BEDROCK_PROMPTS','AWS','REGIONAL','Bedrock prompt metadata discovery.'),
 ('BEDROCK_FLOWS','AWS','REGIONAL','Bedrock flow discovery.'),
 ('SAGEMAKER_DOMAINS','AWS','REGIONAL','SageMaker domain discovery.'),
 ('SAGEMAKER_SPACES','AWS','REGIONAL','SageMaker space discovery.'),
 ('SAGEMAKER_MODEL_REGISTRY','AWS','REGIONAL','SageMaker registry discovery.'),
 ('SAGEMAKER_ENDPOINTS','AWS','REGIONAL','SageMaker endpoint discovery.'),
 ('SAGEMAKER_ENDPOINT_CONFIGURATIONS','AWS','REGIONAL','SageMaker endpoint-configuration discovery.'),
 ('SAGEMAKER_JOBS','AWS','REGIONAL','SageMaker job discovery.'),
 ('SAGEMAKER_PIPELINES','AWS','REGIONAL','SageMaker pipeline discovery.'),
 ('SAGEMAKER_COMPUTE','AWS','REGIONAL','SageMaker compute discovery.'),
 ('SAGEMAKER_EXECUTION_ROLES','AWS','ACCOUNT_GLOBAL','SageMaker execution-role discovery.'),
 ('SAGEMAKER_NETWORKING','AWS','REGIONAL','SageMaker networking discovery.'),
 ('LAMBDA_URLS','AWS','REGIONAL','Lambda URL discovery.'),
 ('S3_EXPOSURE','AWS','REGIONAL','S3 exposure discovery.'),
 ('AWS_MACIE_PII','AWS','REGIONAL','Amazon Macie PII classification discovery.'),
 ('IAM_GLOBAL','AWS','ACCOUNT_GLOBAL','IAM discovery.'),
 ('AZURE_AI_ACCOUNTS','AZURE','REGIONAL','Azure AI account discovery.'),
 ('AZURE_FOUNDRY_PROJECTS','AZURE','REGIONAL','Azure Foundry project discovery.'),
 ('AZURE_FOUNDRY_DEPLOYMENTS','AZURE','REGIONAL','Azure Foundry deployment discovery.'),
 ('AZURE_RAI_POLICIES','AZURE','REGIONAL','Azure RAI policy discovery.'),
 ('AZURE_FOUNDRY_AGENTS','AZURE','REGIONAL','Azure Foundry agent discovery.'),
 ('AZURE_FOUNDRY_AGENT_TOOLS','AZURE','REGIONAL','Azure Foundry tool discovery.'),
 ('AZURE_ML_WORKSPACES','AZURE','REGIONAL','Azure ML workspace discovery.'),
 ('AZURE_ML_MODELS','AZURE','REGIONAL','Azure ML model discovery.'),
 ('AZURE_ML_ENDPOINTS','AZURE','REGIONAL','Azure ML endpoint discovery.'),
 ('AZURE_ML_DEPLOYMENTS','AZURE','REGIONAL','Azure ML deployment discovery.'),
 ('AZURE_ML_COMPUTE','AZURE','REGIONAL','Azure ML compute discovery.'),
 ('AZURE_ML_JOBS','AZURE','REGIONAL','Azure ML job discovery.'),
 ('AZURE_ML_PIPELINES','AZURE','REGIONAL','Azure ML pipeline discovery.'),
 ('AZURE_SEARCH_SERVICES','AZURE','REGIONAL','Azure AI Search service discovery.'),
 ('AZURE_SEARCH_INDEXES','AZURE','REGIONAL','Azure AI Search index discovery.'),
 ('AZURE_SEARCH_SKILLSETS','AZURE','REGIONAL','Azure AI Search skillset discovery.'),
 ('AZURE_SEARCH_INDEXERS','AZURE','REGIONAL','Azure AI Search indexer discovery.'),
 ('AZURE_SEARCH_DATA_SOURCES','AZURE','REGIONAL','Azure AI Search data-source discovery.'),
 ('AZURE_SEARCH_KNOWLEDGE_BASES','AZURE','REGIONAL','Azure AI Search knowledge-base discovery.'),
 ('AZURE_SEARCH_KNOWLEDGE_SOURCES','AZURE','REGIONAL','Azure AI Search knowledge-source discovery.'),
 ('AZURE_BOT_SERVICES','AZURE','ACCOUNT_GLOBAL','Azure Bot service discovery.'),
 ('AZURE_BOT_CHANNELS','AZURE','ACCOUNT_GLOBAL','Azure Bot channel discovery.'),
 ('AZURE_BOT_IDENTITIES','AZURE','ACCOUNT_GLOBAL','Azure Bot identity discovery.'),
 ('AZURE_DIAGNOSTIC_SETTINGS','AZURE','REGIONAL','Azure diagnostic-settings discovery.'),
 ('AZURE_RBAC_GLOBAL','AZURE','ACCOUNT_GLOBAL','Azure RBAC discovery.'),
 ('AZURE_RBAC_ASSIGNMENTS','AZURE','REGIONAL','Azure RBAC assignment discovery.'),
 ('AZURE_PURVIEW_CLASSIFICATION','AZURE','REGIONAL','Azure Purview classification discovery.')
ON CONFLICT (resource_family) DO NOTHING;

INSERT INTO platform.ai_grid_relationship_definitions (relationship_type,source,description)
VALUES
 ('USES_MODEL','OBSERVATION_V1','Artifact uses a model.'),
 ('USES_GUARDRAIL','OBSERVATION_V1','Artifact uses a guardrail.'),
 ('USES_KNOWLEDGE_BASE','OBSERVATION_V1','Artifact uses a knowledge base.'),
 ('USES_DATA_SOURCE','OBSERVATION_V1','Artifact uses a data source.'),
 ('BACKED_BY_DATA_STORE','OBSERVATION_V1','Artifact is backed by a data store.'),
 ('USES_SEARCH_INDEX','OBSERVATION_V1','Artifact uses a search index.'),
 ('EXPOSES_MCP','OBSERVATION_V1','Artifact exposes MCP.'),
 ('CONNECTS_TO_MCP','OBSERVATION_V1','Artifact connects to MCP.'),
 ('CONTAINS_MCP_TARGET','OBSERVATION_V1','Gateway contains an MCP target.'),
 ('ROUTES_TO','OBSERVATION_V1','Artifact routes to another artifact.'),
 ('INVOKES_LAMBDA','OBSERVATION_V1','Artifact invokes Lambda.'),
 ('ASSUMES_ROLE','OBSERVATION_V1','Artifact assumes a role.'),
 ('READS_FROM_S3','OBSERVATION_V1','Artifact reads from S3.'),
 ('LOGS_TO','OBSERVATION_V1','Artifact logs to a destination.'),
 ('SUPERVISES_AGENT','OBSERVATION_V1','Artifact supervises an agent.'),
 ('CONTAINS_PROJECT','OBSERVATION_V1','Artifact contains a project.'),
 ('DEPLOYS_MODEL','OBSERVATION_V1','Artifact deploys a model.'),
 ('USES_TOOL','OBSERVATION_V1','Artifact uses a tool.'),
 ('USES_MANAGED_IDENTITY','OBSERVATION_V1','Artifact uses managed identity.'),
 ('HAS_PRIVATE_ENDPOINT','OBSERVATION_V1','Artifact has a private endpoint.'),
 ('USES_KEY_VAULT_KEY','OBSERVATION_V1','Artifact uses a Key Vault key.'),
 ('CONTAINS_RESOURCE','OBSERVATION_V1','Artifact contains a resource.'),
 ('HAS_DEPLOYMENT','OBSERVATION_V1','Artifact has a deployment.'),
 ('RUNS_PIPELINE','OBSERVATION_V1','Artifact runs a pipeline.'),
 ('HAS_CHANNEL','OBSERVATION_V1','Artifact has a channel.'),
 ('HAS_ROLE_ASSIGNMENT','OBSERVATION_V1','Artifact has a role assignment.'),
 ('CONTAINS','OBSERVATION_V1','Artifact contains another artifact.'),
 ('USES_EXECUTION_ROLE','OBSERVATION_V1','Artifact uses an execution role.'),
 ('USES_NETWORK','OBSERVATION_V1','Artifact uses a network.'),
 ('USES_ENDPOINT_CONFIGURATION','OBSERVATION_V1','Artifact uses endpoint configuration.'),
 ('PRODUCES_MODEL','OBSERVATION_V1','Artifact produces a model.'),
 ('USES_DATA_CONNECTION','OBSERVATION_V1','Artifact uses a data connection.'),
 ('READS_FROM_STORAGE_ACCOUNT','OBSERVATION_V1','Artifact reads from a storage account.'),
 ('DIRECT_PROVIDER_RELATIONSHIP','AI_GRID_GRAPH','Governed one-hop graph evaluation profile.')
ON CONFLICT (relationship_type) DO NOTHING;


-- source: V78__ai_grid_phase_1_additional_correlations.sql
-- The three Phase 1 correlation definitions that complement the three retained R2 definitions.
INSERT INTO platform.ai_grid_correlation_versions
    (correlation_id,version,name,description,lifecycle,severity,precision_threshold,
     max_path_depth,max_fan_out,allowed_node_types_json,allowed_edge_types_json,
     requirements_json,approved_by,approved_at,published_at)
VALUES
('R2_EXTERNAL_MCP_SENSITIVE_ACCESS','1.0.0','External or unapproved MCP path to sensitive data',
 'An MCP server that is externally reachable or unapproved is connected to an AI path with confirmed sensitive-data access.',
 'PUBLISHED','CRITICAL',0.95,6,100,
 '["AI_AGENT","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["EXPOSES_MCP","CONNECTS_TO_MCP","CONTAINS_MCP_TARGET","USES_DATA_SOURCE","USES_SEARCH_INDEX","READS_FROM_S3"]',
 '{"validated":["mcp.external_or_unapproved_verified","data.sensitive_access_confirmed"],"hypothesis":["mcp.configured_auth_type","mcp.inbound_auth_type","mcp.outbound_auth_type","data.source_linked"]}',
 'ai-grid-phase-1',now(),now()),
('R2_MCP_WEAK_AUTH_EXECUTION','1.0.0','High-impact execution through an MCP target with weak authentication',
 'An autonomous or high-impact AI agent routes through an MCP target whose authentication is absent or unknown.',
 'PUBLISHED','HIGH',0.93,6,100,
 '["AI_AGENT","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_TOOL","EXPOSES_MCP","CONNECTS_TO_MCP","CONTAINS_MCP_TARGET","INVOKES_LAMBDA"]',
 '{"validated":["agent.autonomous_execution_verified","mcp.auth_inadequate_verified"],"hypothesis":["agent.code_interpreter_enabled_configured","mcp.configured_auth_type","mcp.inbound_auth_type","mcp.outbound_auth_type"]}',
 'ai-grid-phase-1',now(),now()),
('R2_SENSITIVE_RETRIEVAL_CONTROL_GAP','1.0.0','Sensitive retrieval path without required guardrail or PII baseline',
 'An agent can retrieve sensitive data while the required guardrail or PII-filter baseline is absent.',
 'PUBLISHED','HIGH',0.92,6,100,
 '["AI_AGENT","AI_GUARDRAIL","KNOWLEDGE_BASE","SUPPORTING_RESOURCE","OTHER_AI_ARTIFACT"]',
 '["USES_KNOWLEDGE_BASE","USES_DATA_SOURCE","USES_SEARCH_INDEX","USES_GUARDRAIL","READS_FROM_S3"]',
 '{"validated":["data.sensitive_access_confirmed","control.execution_boundary_inadequate_verified"],"hypothesis":["data.source_linked","bedrock.agent.guardrail_attached_configured","bedrock.guardrail.minimum_strength_configured","guardrail.rai_non_blocking_filter_observed"]}',
 'ai-grid-phase-1',now(),now())
ON CONFLICT (correlation_id,version) DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,
     allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('mcp.external_or_unapproved_verified','1.0.0','BOOLEAN',
 'Approved graph or runtime evidence verifies that an MCP endpoint is external or unapproved.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
('mcp.auth_inadequate_verified','1.0.0','BOOLEAN',
 'Approved graph or runtime evidence verifies inadequate authentication for an MCP target.',
 '["GRAPH_ANALYSIS","ACTIVE_TEST","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600)
ON CONFLICT (fact_key,version) DO NOTHING;


-- source: V79__ai_grid_phase_1_release_metadata.sql
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS release_family varchar(128),
    ADD COLUMN IF NOT EXISTS release_wave varchar(128);

UPDATE platform.ai_grid_policy_versions
   SET release_family = coalesce(release_family, 'AGCF_PHASE_1'),
       release_wave = coalesce(release_wave, 'PHASE_1')
 WHERE policy_id LIKE 'AGCF-%';

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_release_family_check
        CHECK (release_family IS NULL OR length(trim(release_family)) > 0),
    ADD CONSTRAINT ai_grid_policy_release_wave_check
        CHECK (release_wave IS NULL OR length(trim(release_wave)) > 0);


-- source: V80__ai_grid_phase_1_legacy_migration_ledger.sql
-- Records approved Phase 1 replacements and retirements without changing historic tenant evidence.
CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_migration_ledger (
    legacy_detector_id varchar(128) PRIMARY KEY,
    legacy_detector_kind varchar(32) NOT NULL,
    legacy_version varchar(32) NOT NULL DEFAULT '1.0.0',
    disposition varchar(48) NOT NULL,
    successor_policy_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    closure_reason varchar(128),
    rationale text NOT NULL,
    approved_by varchar(255) NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    CHECK (legacy_detector_kind IN ('POSTURE_POLICY','CORRELATION')),
    CHECK (disposition IN ('ONE_TO_ONE_REPLACEMENT','SPLIT_REPLACEMENT','RETAINED_GOVERNED_ENVELOPE','RETIRED_INSUFFICIENT_EVIDENCE')),
    CHECK ((disposition = 'RETIRED_INSUFFICIENT_EVIDENCE') = (closure_reason IS NOT NULL))
);

INSERT INTO platform.ai_grid_policy_migration_ledger
    (legacy_detector_id, legacy_detector_kind, disposition, successor_policy_ids_json, closure_reason, rationale, approved_by)
VALUES
('AWS_BEDROCK_WEAK_GUARDRAIL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-002"]',NULL,'Equivalent guardrail-strength evidence is preserved by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_PUBLIC_KB_S3','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-017"]',NULL,'Public knowledge-base source posture is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_UNAUTH_LAMBDA_URL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-006"]',NULL,'Lambda URL authentication evidence is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_WILDCARD_AGENT_ROLE','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-005"]',NULL,'Wildcard execution-role evidence is represented by the governed adapter.','ai-grid-phase-1'),
('AWS_BEDROCK_INVOCATION_LOGGING_DISABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-009"]',NULL,'Invocation logging posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_RAI_POLICY_NON_BLOCKING_FILTER','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-010"]',NULL,'RAI filter behavior is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-001"]',NULL,'Public network access posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_LOCAL_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-003"]',NULL,'Local authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-005"]',NULL,'Diagnostic logging posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-017"]',NULL,'Foundry code-interpreter posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-022"]',NULL,'ML endpoint local authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-026"]',NULL,'Search local-admin authentication posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-027"]',NULL,'Bot credential posture is represented by the governed adapter.','ai-grid-phase-1'),
('MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-033"]',NULL,'MCP target health posture is represented by the governed adapter.','ai-grid-phase-1'),
('SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-024"]',NULL,'Sensitive public data-source posture is represented by the governed adapter.','ai-grid-phase-1'),
('BEDROCK_GUARDRAIL_NOT_ATTACHED','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AWS-001"]',NULL,'Guardrail attachment posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_BOT_MANAGED_IDENTITY_MISSING','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-028"]',NULL,'Bot managed-identity posture is represented by the governed adapter.','ai-grid-phase-1'),
('AZURE_RBAC_BROAD_ASSIGNMENT','POSTURE_POLICY','ONE_TO_ONE_REPLACEMENT','["AGCF-AZR-030"]',NULL,'Azure RBAC posture is represented by the governed adapter.','ai-grid-phase-1'),
('BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING','POSTURE_POLICY','SPLIT_REPLACEMENT','["AGCF-AWS-003","AGCF-AWS-004"]',NULL,'The legacy combined control is separated into operational-state and role-presence adapters.','ai-grid-phase-1'),
('MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH','POSTURE_POLICY','RETIRED_INSUFFICIENT_EVIDENCE','[]','POLICY_RETIRED_INSUFFICIENT_EVIDENCE','Authoritative public reachability evidence is not available in Phase 1.','ai-grid-phase-1'),
('AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH','POSTURE_POLICY','RETIRED_INSUFFICIENT_EVIDENCE','[]','POLICY_RETIRED_INSUFFICIENT_EVIDENCE','A secret-safe Search data-source authentication classifier is not available in Phase 1.','ai-grid-phase-1'),
('R2_EXTERNAL_SENSITIVE_ACCESS','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-001"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1'),
('R2_EXCESSIVE_TOOL_PRIVILEGE','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-003"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1'),
('R2_UNTRUSTED_AUTONOMOUS_EXECUTION','CORRELATION','RETAINED_GOVERNED_ENVELOPE','["AGCF-XSP-002"]',NULL,'The existing published correlation is governed by its AGCF exposure envelope.','ai-grid-phase-1')
ON CONFLICT (legacy_detector_id) DO NOTHING;


-- source: V81__ai_grid_phase_1_tenant_migration_audit.sql
-- Immutable operator record for a tenant-scoped application of the approved Phase 1 ledger.
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_tenant_migration_audit (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    ledger_version varchar(64) NOT NULL,
    applied_by varchar(255) NOT NULL,
    legacy_selection_count integer NOT NULL,
    selection_copy_count integer NOT NULL,
    retirement_count integer NOT NULL,
    open_findings_closed integer NOT NULL,
    manual_configuration_review_count integer NOT NULL,
    actions_json jsonb NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_phase_1_migration_audit_tenant
    ON platform.ai_grid_phase_1_tenant_migration_audit (tenant_id, applied_at DESC);


-- source: V82__ai_grid_precision_sample_provenance.sql
-- New precision samples must be traceable to an immutable tenant assessment/run. Existing
-- historical samples remain readable but are explicitly legacy-unbound and cannot pass a current gate.
ALTER TABLE platform.ai_grid_precision_samples
    ADD COLUMN IF NOT EXISTS source_tenant_id uuid REFERENCES platform.tenants(id),
    ADD COLUMN IF NOT EXISTS source_run_id uuid,
    ADD COLUMN IF NOT EXISTS source_assessment_id uuid,
    ADD COLUMN IF NOT EXISTS source_decision_fingerprint varchar(128),
    ADD COLUMN IF NOT EXISTS provenance_state varchar(32) NOT NULL DEFAULT 'LEGACY_UNBOUND';

ALTER TABLE platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_sample_provenance_state_chk
    CHECK (provenance_state IN ('PLATFORM_RUN_BOUND', 'LEGACY_UNBOUND'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_grid_precision_sample_source_assessment
    ON platform.ai_grid_precision_samples (review_id, source_assessment_id)
    WHERE source_assessment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_grid_precision_sample_source_run
    ON platform.ai_grid_precision_samples (source_tenant_id, source_run_id, source_assessment_id);


-- source: V83__ai_grid_phase_1_release_safety_pause.sql
-- Phase 1 catalog records are installed before external certification, but they must never be
-- tenant-visible or published until the governed release gate approves their package digest.
UPDATE platform.ai_grid_policy_distribution d
   SET available = false, rollout_stage = 'PAUSED', updated_by = 'ai-grid-phase-1-release-safety', updated_at = now()
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p
                WHERE p.policy_id = d.policy_id AND p.release_family = 'AGCF_PHASE_1')
   AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions decision
                    JOIN platform.ai_grid_policy_versions p ON p.policy_id = decision.policy_id
                        AND p.version = decision.policy_version
                   WHERE decision.policy_id = d.policy_id AND decision.decision = 'APPROVED'
                     AND p.release_family = 'AGCF_PHASE_1');

UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED', approved_by = null, approved_at = null, published_at = null
 WHERE release_family = 'AGCF_PHASE_1' AND lifecycle = 'PUBLISHED'
   AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions decision
                   WHERE decision.policy_id = ai_grid_policy_versions.policy_id
                     AND decision.policy_version = ai_grid_policy_versions.version
                     AND decision.decision = 'APPROVED');


-- source: V84__ai_grid_phase_1_release_board.sql
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_release_gate_evidence (
    id uuid PRIMARY KEY,
    gate_key varchar(64) NOT NULL,
    status varchar(16) NOT NULL,
    evidence_json jsonb NOT NULL,
    recorded_by varchar(255) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (gate_key IN ('CANARY_AWS','CANARY_AZURE','CANARY_MULTI_CLOUD','PERFORMANCE','ROLLBACK_AWS','ROLLBACK_AZURE','ROLLBACK_MULTI_CLOUD')),
    CHECK (status IN ('PASSED','FAILED'))
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_phase_1_release_gate_latest
    ON platform.ai_grid_phase_1_release_gate_evidence (gate_key, recorded_at DESC);


-- source: V85__ai_grid_phase_1_retired_detector_backlog.sql
-- Seeds connector-capability backlog candidates for the detectors retired in the Phase 1
-- catalog migration (V80) for insufficient evidence. Each carries machine-readable
-- reactivation criteria so the deprecation is tracked, not silently dropped. Idempotent:
-- fixed ids + ON CONFLICT DO NOTHING.
INSERT INTO platform.ai_grid_policy_candidates
    (id, title, source_type, status, technology_id, rationale,
     risk_score, reach_score, evidence_maturity, remediation_clarity, owner, created_by)
VALUES
('5523bc91-acd7-43c0-bfb3-b357726d65b3',
 'Public MCP endpoint reachable without configured authentication',
 'CONNECTOR_CAPABILITY', 'COLLECTOR_BACKLOG', 'AWS_BEDROCK_AGENTCORE',
 'Retired from Phase 1 (POLICY_RETIRED_INSUFFICIENT_EVIDENCE): collectors persist EXTERNAL_ENDPOINT but not authoritative PUBLIC_NETWORK_REACHABLE. Reactivation criteria: add consented, non-invasive reachability verification or provider network-policy metadata that authoritatively proves public reachability. Never infer reachability from a URL.',
 3, 2, 1, 2, 'ai-grid-phase-1', 'ai-grid-phase-1'),
('b8320126-7259-43eb-a6ee-5ebb714e52a9',
 'Azure AI Search data-source non-identity authentication',
 'CONNECTOR_CAPABILITY', 'COLLECTOR_BACKLOG', 'AZURE_AI_SEARCH',
 'Retired from Phase 1 (POLICY_RETIRED_INSUFFICIENT_EVIDENCE): connection strings are intentionally not persisted, so non-identity authentication cannot be proven. Reactivation criteria: implement a secret-safe Search data-plane auth classifier that persists only MANAGED_IDENTITY | KEY_OR_SAS | UNKNOWN, never secret material.',
 3, 2, 1, 2, 'ai-grid-phase-1', 'ai-grid-phase-1')
ON CONFLICT (id) DO NOTHING;


-- source: V86__ai_grid_next_target_connector_backlog.sql
-- Seeds the governed next-target connector-capability backlog from the Phase 1 plan's
-- enhancement categories. These are forward-looking candidates (RESEARCH), not shipped
-- coverage, so the backlog is funded and bounded rather than implicit. Idempotent:
-- fixed ids + ON CONFLICT DO NOTHING. Evidence-maturity is deliberately low (evidence
-- is not yet collectable); risk/reach reflect plan priority ordering.
INSERT INTO platform.ai_grid_policy_candidates
    (id, title, source_type, status, technology_id, rationale,
     risk_score, reach_score, evidence_maturity, remediation_clarity, owner, created_by)
VALUES
('893b8993-6316-466e-bf2e-0b3501d3e753',
 'Effective AWS IAM and Azure RBAC decisions',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #1: resolve effective permissions (IAM SimulatePrincipalPolicy / Access Analyzer; Azure role definitions, deny assignments, PIM) to decide excessive-agency posture. Store decisions, not raw sensitive policy bodies.',
 5, 5, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('63d5c39a-2ae9-43e9-af9f-8cad83af5fba',
 'Referenced backing-store network, encryption, and authentication metadata',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #2: enrich directly referenced S3 / Azure Storage / Search / vector-store resources with public-access-block, encryption (CMK), TLS, and private-endpoint metadata. Preserve account-level ambiguity as NO_DECISION.',
 5, 4, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('9844ab16-eef2-47e7-8555-4e10e362e93b',
 'Secret-safe Search/MCP auth classification, ACL, retrieval mode, private endpoint',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #3: classify Search/MCP authentication in memory (MANAGED_IDENTITY | KEY_OR_SAS | UNKNOWN), extract ACL/permission-filter and retrieval-mode metadata, and emit authoritative private-endpoint state. Never persist secrets or connection strings.',
 4, 4, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('e5642902-fd08-4029-952f-edba68de8bcf',
 'Bedrock and Azure consumption, quota, budget, and alarm telemetry',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #4: add CloudWatch / Azure Monitor invocation, token, throttle and quota-usage metrics plus Budgets / Cost Management and alarm inventory to decide unbounded-consumption posture. Prefer counters over prompt/output bodies.',
 3, 4, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('147bc58c-be61-4803-b7af-eac27771eec6',
 'Model/data provenance, signatures, registry lineage, SBOM/AI-BOM, and vulnerabilities',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #5: add model-registry / ECR / ACR attestation, MLflow lineage, checksums/signatures, and SBOM/AI-BOM + vulnerability evidence for supply-chain and data-poisoning coverage (AICM MDS/STA). Resolve only referenced artifacts; never read object content.',
 4, 3, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('d3ba37fa-e266-4b87-af36-49e4948a5fbc',
 'Opt-in runtime prompt-injection, content-safety, output-handling, and reachability evidence',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #6: behind explicit consent, add runtime guardrail/content-safety verdicts, evaluation results, and non-invasive reachability verification for LLM01/07/08/10 runtime signals. Store test ids, scores, and hashes rather than prompt/output bodies; never infer public reachability from a URL.',
 3, 3, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1')
ON CONFLICT (id) DO NOTHING;


-- source: V87__restore_legacy_ai_grid_policies_while_phase_1_is_paused.sql
-- V76 installed the Phase 1 catalog and retired the predecessor policies.  Phase 1 is
-- subsequently held at VALIDATED/PAUSED until its external certification gates pass.
-- Keep the previously released controls operating during that hold; a governed
-- migration can retire each predecessor only when its replacement is approved.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM platform.ai_grid_policy_versions
         WHERE release_family = 'AGCF_PHASE_1'
           AND lifecycle = 'PUBLISHED'
    ) THEN
        UPDATE platform.ai_grid_policy_versions
           SET lifecycle = 'PUBLISHED'
         WHERE policy_id NOT LIKE 'AGCF-%'
           AND lifecycle = 'RETIRED';

        UPDATE platform.ai_grid_policy_distribution
           SET available = default_selection <> 'DISABLED',
               rollout_stage = CASE
                   WHEN default_selection = 'DISABLED' THEN 'PAUSED'
                   ELSE 'GENERAL_AVAILABILITY'
               END,
               updated_by = 'ai-grid-phase-1-release-safety',
               updated_at = now()
         WHERE policy_id NOT LIKE 'AGCF-%'
           AND rollout_stage = 'RETIRED';
    END IF;
END $$;


-- source: V88__ai_grid_phase_1_typed_and_correlation_contracts.sql
-- Forward-only correction for VALIDATED/PAUSED Phase 1 packages. V76 is intentionally immutable.

UPDATE platform.ai_grid_fact_definitions
   SET value_type = 'STRING'
 WHERE fact_key = 'mcp.target_status'
   AND version = '1.0.0'
   AND value_type = 'BOOLEAN';

UPDATE platform.ai_grid_policy_versions
   SET required_facts_json = '[{"factKey":"mcp.target_status","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]'::jsonb,
       predicate_json = '{"fact":"mcp.target_status","in":["FAILED","UNSYNCHRONIZED"]}'::jsonb,
       package_digest = '4bdf2363a456f890530f521b818c38c702418b1137b20437c1d9efcabef1ea73'
 WHERE policy_id = 'AGCF-AWS-033'
   AND version = '1.0.0'
   AND lifecycle = 'VALIDATED';

UPDATE platform.ai_grid_policy_versions
   SET required_facts_json = '[]'::jsonb,
       predicate_json = '{}'::jsonb,
       package_digest = CASE policy_id
           WHEN 'AGCF-XSP-001' THEN '567ca24019a78b5ed67a3c6c92f03bf88c49cfab67f76a4cdc055c9973c8cdf5'
           WHEN 'AGCF-XSP-002' THEN '323e12ffd312f1c9159941fd8064ccdb0dd14ebe169ba4dad20f7049b4e353a4'
           WHEN 'AGCF-XSP-003' THEN '79ff72666cda3d9e35fe7259bca45aa8998d32e849454f23d4829a80c321686b'
           WHEN 'AGCF-XSP-004' THEN 'a3ced46f504b5e27af0ab59f6ce3767f3fbfd445e2b3845b9ed9b5891e3377fa'
           WHEN 'AGCF-XSP-005' THEN 'eae2d68b420c3704c92c18bd0bd84f46b5d46936b6c4327512d3fc153c98701b'
           WHEN 'AGCF-XSP-006' THEN 'b4b426318f7bbb944e1d2d542aefd780d9552c22fa9eb4ff871d17ef049ce867'
       END
 WHERE policy_id IN ('AGCF-XSP-001','AGCF-XSP-002','AGCF-XSP-003','AGCF-XSP-004','AGCF-XSP-005','AGCF-XSP-006')
   AND version = '1.0.0'
   AND lifecycle = 'VALIDATED';



-- source: V89__ai_grid_phase_1_concrete_evidence_contracts.sql
-- Forward-only replacement of the 31 remaining generic Phase 1 evidence contracts.
-- Generated by scripts/compile-ai-grid-phase1.mjs; V76 and V88 remain immutable.

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,allowed_workflow_uses_json,default_max_age_seconds)
VALUES
('agent.tool_type_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('bot.channel_type_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('compute.instance_type_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('compute.lambda_target_arn_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.customer_managed_key_configured','1.0.0','BOOLEAN','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.deletion_policy_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.s3_public_access_configured','1.0.0','BOOLEAN','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.sensitivity_confirmed','1.0.0','BOOLEAN','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.source_public_content_access','1.0.0','BOOLEAN','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.source_sensitivity','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('data.source_type','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.contextual_grounding_filter_count_configured','1.0.0','NUMBER','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.denied_topic_count_configured','1.0.0','NUMBER','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.pii_entity_count_configured','1.0.0','NUMBER','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.rai_base_policy_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.rai_custom_blocklist_count_configured','1.0.0','NUMBER','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.rai_mode_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('guardrail.updated_at_observed','1.0.0','TIMESTAMP','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('identity.assignment_condition_version_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('identity.assignment_scope_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('identity.principal_type_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('mcp.server_hostname_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('mcp.target_subtype_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('ml.endpoint_traffic_configured','1.0.0','OBJECT','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('ml.model_reference_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.foundation_identifier_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.name_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.provider_name_observed','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.publisher_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.version_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('model.version_upgrade_option_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('network.vpc_id_configured','1.0.0','STRING','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400),
('resource.required_tags_present_configured','1.0.0','BOOLEAN','Canonical provider-observed Phase 1 evidence.','["CONFIGURATION"]','["POSTURE_FINDING"]'::jsonb,86400)
ON CONFLICT (fact_key,version) DO NOTHING;

WITH corrections(policy_id,version,artifact_types_json,native_kinds_json,required_facts_json,predicate_json,parameter_definitions_json,evaluation_definition_json,certification_parameter_profile_json,package_digest) AS (VALUES
('AGCF-AWS-007','1.0.0','[]','["AWS_BEDROCK_AGENT"]','[{"factKey":"model.foundation_identifier_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"model.foundation_identifier_configured","in":{"parameter":"approvedFoundationModels"}}}','[{"key":"approvedFoundationModels","type":"STRING_LIST","defaultValue":["amazon.nova-pro-v1:0"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"model.foundation_identifier_configured","in":{"parameter":"approvedFoundationModels"}}}}}','{"immutable":true,"pass":{"approvedFoundationModels":["amazon.nova-pro-v1:0"]},"fail":{"approvedFoundationModels":[]},"invalid":{}}','c5f26b8ee3025e38fac0de9934ac2fec0416dfc3dc7a7507703e845700703d0d'),
('AGCF-AWS-008','1.0.0','[]','["AWS_LAMBDA_FUNCTION"]','[{"factKey":"compute.lambda_target_arn_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"compute.lambda_target_arn_configured","in":{"parameter":"approvedLambdaTargets"}}}','[{"key":"approvedLambdaTargets","type":"STRING_LIST","defaultValue":[]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"compute.lambda_target_arn_configured","in":{"parameter":"approvedLambdaTargets"}}}}}','{"immutable":true,"pass":{"approvedLambdaTargets":[]},"fail":{"approvedLambdaTargets":["CERTIFICATION_APPROVED_VALUE"]},"invalid":{}}','bcc5079c3e41c5ca3fcec48f47147c944175b6cdb6c56b2b568447db01bc1820'),
('AGCF-AWS-011','1.0.0','[]','["AWS_BEDROCK_GUARDRAIL"]','[{"factKey":"data.customer_managed_key_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.customer_managed_key_configured","eq":false}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.customer_managed_key_configured","eq":false}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','70e9125c5ba32cd287ba3322ffa14cbb9a5c95f735bebb66fb8f89395d427c70'),
('AGCF-AWS-013','1.0.0','[]','["AWS_BEDROCK_GUARDRAIL"]','[{"factKey":"guardrail.pii_entity_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.pii_entity_count_configured","count_eq":0}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.pii_entity_count_configured","count_eq":0}}}','null','0daf0ba1ec81731f8e782d13b139b20d589b23a76e2299d86787c9b147d3cc7f'),
('AGCF-AWS-014','1.0.0','[]','["AWS_BEDROCK_GUARDRAIL"]','[{"factKey":"guardrail.contextual_grounding_filter_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.contextual_grounding_filter_count_configured","count_eq":0}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.contextual_grounding_filter_count_configured","count_eq":0}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','fa164a3d3e54e982d8e5bfa7e8ef8b2a082b46ebe83ac50676b4b28eb0176311'),
('AGCF-AWS-015','1.0.0','[]','["AWS_BEDROCK_GUARDRAIL"]','[{"factKey":"guardrail.denied_topic_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.denied_topic_count_configured","count_eq":0}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.denied_topic_count_configured","count_eq":0}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','03fe4ee1a898e9911bb451e06241d8c66a4719352af284c5d2c2ccd2a621b60d'),
('AGCF-AWS-016','1.0.0','[]','["AWS_BEDROCK_GUARDRAIL"]','[{"factKey":"guardrail.updated_at_observed","valueType":"TIMESTAMP","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.updated_at_observed","age_gt_seconds":{"parameter":"maximumReviewAgeSeconds"}}','[{"key":"maximumReviewAgeSeconds","type":"NUMBER","defaultValue":7776000}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.updated_at_observed","age_gt_seconds":{"parameter":"maximumReviewAgeSeconds"}}}}','{"immutable":true,"pass":{"maximumReviewAgeSeconds":7776000},"fail":{"maximumReviewAgeSeconds":7776001},"invalid":{}}','778ae167091447fb92db54181ddf4a768550af403fae67397ba98ba46c437ce2'),
('AGCF-AWS-017','1.0.0','[]','["AWS_BEDROCK_KNOWLEDGE_BASE"]','[{"factKey":"data.s3_public_access_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.s3_public_access_configured","eq":true}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.s3_public_access_configured","eq":true}}}','null','c81709c49655fb8f6c9706071cd6f2eb7a8d40a98cf08943a1e2d1aebcba4281'),
('AGCF-AWS-021','1.0.0','[]','["AWS_BEDROCK_DATA_SOURCE"]','[{"factKey":"data.source_type","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"data.source_type","in":{"parameter":"approvedSourceTypes"}}}','[{"key":"approvedSourceTypes","type":"STRING_LIST","defaultValue":["S3"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"data.source_type","in":{"parameter":"approvedSourceTypes"}}}}}','{"immutable":true,"pass":{"approvedSourceTypes":["S3"]},"fail":{"approvedSourceTypes":[]},"invalid":{}}','f5c2d82e00588f3674ba9efa91e322771d3a310b10a02b1611c3bf3d9f2d1132'),
('AGCF-AWS-022','1.0.0','[]','["AWS_BEDROCK_DATA_SOURCE"]','[{"factKey":"data.deletion_policy_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"data.deletion_policy_configured","in":{"parameter":"approvedDeletionPolicies"}}}','[{"key":"approvedDeletionPolicies","type":"STRING_LIST","defaultValue":["RETAIN"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"data.deletion_policy_configured","in":{"parameter":"approvedDeletionPolicies"}}}}}','{"immutable":true,"pass":{"approvedDeletionPolicies":["RETAIN"]},"fail":{"approvedDeletionPolicies":[]},"invalid":{}}','fe2e45d89d8a1e151c07fbf87ebd343a4d3429bc57d1305d571b78fa2d99e081'),
('AGCF-AWS-023','1.0.0','[]','["AWS_S3_DATA_STORE"]','[{"factKey":"data.source_sensitivity","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.source_sensitivity","in":["NOT_SCANNED"]}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.source_sensitivity","in":["NOT_SCANNED"]}}}','null','2450b81e6944a4de7834578bd131eae763e9b561b4a220a45d754e4c238af178'),
('AGCF-AWS-024','1.0.0','[]','["AWS_S3_DATA_STORE"]','[{"factKey":"data.sensitivity_confirmed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"data.source_public_content_access","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"all":[{"fact":"data.sensitivity_confirmed","eq":true},{"fact":"data.source_public_content_access","eq":true}]}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"all":[{"fact":"data.sensitivity_confirmed","eq":true},{"fact":"data.source_public_content_access","eq":true}]}}}','null','0749263628a7365722aeaf016d90ef808fb96ae1c286a00d4860551e2c103a0b'),
('AGCF-AWS-025','1.0.0','[]','["AWS_BEDROCK_CUSTOM_MODEL"]','[{"factKey":"data.customer_managed_key_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.customer_managed_key_configured","eq":false}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.customer_managed_key_configured","eq":false}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','7f88b6a43787110889dc9b1583fba746974bb415eb616cb6ea2a2f0bd67a5f16'),
('AGCF-AWS-026','1.0.0','[]','["AWS_BEDROCK_IMPORTED_MODEL"]','[{"factKey":"data.customer_managed_key_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.customer_managed_key_configured","eq":false}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.customer_managed_key_configured","eq":false}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','495f36523c57230f4f8ca255edbad10d2b6d8bb122e21c2710615a358c959409'),
('AGCF-AWS-028','1.0.0','[]','["AWS_BEDROCK_MODEL"]','[{"factKey":"model.provider_name_observed","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"model.provider_name_observed","in":{"parameter":"approvedModelProviders"}}}','[{"key":"approvedModelProviders","type":"STRING_LIST","defaultValue":["Amazon"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"model.provider_name_observed","in":{"parameter":"approvedModelProviders"}}}}}','{"immutable":true,"pass":{"approvedModelProviders":["Amazon"]},"fail":{"approvedModelProviders":[]},"invalid":{}}','1663017309cdab574695350eb7991f2e5cf2e3687ac6c61772afa1f252ebeb72'),
('AGCF-AWS-034','1.0.0','[]','["AWS_AGENTCORE_GATEWAY_TARGET","AWS_AGENTCORE_MCP_SERVER"]','[{"factKey":"mcp.target_subtype_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"mcp.server_hostname_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"not":{"fact":"mcp.target_subtype_configured","in":{"parameter":"approvedMcpTargetSubtypes"}}},{"not":{"fact":"mcp.server_hostname_configured","in":{"parameter":"approvedMcpServerHosts"}}}]}','[{"key":"approvedMcpTargetSubtypes","type":"STRING_LIST","defaultValue":["MCP","NOT_APPLICABLE"]},{"key":"approvedMcpServerHosts","type":"STRING_LIST","defaultValue":["NOT_APPLICABLE"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"not":{"fact":"mcp.target_subtype_configured","in":{"parameter":"approvedMcpTargetSubtypes"}}},{"not":{"fact":"mcp.server_hostname_configured","in":{"parameter":"approvedMcpServerHosts"}}}]}}}','{"immutable":true,"pass":{"approvedMcpTargetSubtypes":["MCP","NOT_APPLICABLE"],"approvedMcpServerHosts":["NOT_APPLICABLE"]},"fail":{"approvedMcpTargetSubtypes":[],"approvedMcpServerHosts":[]},"invalid":{}}','ec0fda076147ef9fda7f052d68526f7d44421f68b7f302c35c0576b2449769aa'),
('AGCF-AWS-035','1.0.0','[]','["AWS_SAGEMAKER_DOMAIN"]','[{"factKey":"network.vpc_id_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"network.vpc_id_configured","empty":true}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"network.vpc_id_configured","empty":true}}}','null','fa6ec0b035f4c2813bf03e587c81caa1ee6577ee885b411a0d4761d0868e0d59'),
('AGCF-AWS-037','1.0.0','[]','["AWS_SAGEMAKER_NOTEBOOK_INSTANCE"]','[{"factKey":"compute.instance_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"compute.instance_type_configured","in":{"parameter":"approvedComputeTypes"}}}','[{"key":"approvedComputeTypes","type":"STRING_LIST","defaultValue":["ml.t3.medium"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"compute.instance_type_configured","in":{"parameter":"approvedComputeTypes"}}}}}','{"immutable":true,"pass":{"approvedComputeTypes":["ml.t3.medium"]},"fail":{"approvedComputeTypes":[]},"invalid":{}}','245ab3b4510eb6d35449a8b83151815f87bf2645bace43de5a04043d3c7409e3'),
('AGCF-AZR-009','1.0.0','[]','["AZURE_AI_ACCOUNTS","AZURE_ML_WORKSPACES","AZURE_SEARCH_SERVICES"]','[{"factKey":"resource.required_tags_present_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"resource.required_tags_present_configured","eq":false}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"resource.required_tags_present_configured","eq":false}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','fba9bbe063c2d6c3de03617cba17e13e07fb0b7df64bc51ebfcb9565ca26990b'),
('AGCF-AZR-013','1.0.0','[]','["AZURE_RAI_POLICIES"]','[{"factKey":"guardrail.rai_mode_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"guardrail.rai_base_policy_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"not":{"fact":"guardrail.rai_mode_configured","in":{"parameter":"approvedRaiModes"}}},{"not":{"fact":"guardrail.rai_base_policy_configured","in":{"parameter":"approvedRaiBasePolicies"}}}]}','[{"key":"approvedRaiModes","type":"STRING_LIST","defaultValue":["Default"]},{"key":"approvedRaiBasePolicies","type":"STRING_LIST","defaultValue":["Microsoft.Default"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"not":{"fact":"guardrail.rai_mode_configured","in":{"parameter":"approvedRaiModes"}}},{"not":{"fact":"guardrail.rai_base_policy_configured","in":{"parameter":"approvedRaiBasePolicies"}}}]}}}','{"immutable":true,"pass":{"approvedRaiModes":["Default"],"approvedRaiBasePolicies":["Microsoft.Default"]},"fail":{"approvedRaiModes":[],"approvedRaiBasePolicies":[]},"invalid":{}}','f96a0dae89e8fdf73c32a91a3635e09cbd5b9f8e97ecbe30e222888d50028384'),
('AGCF-AZR-014','1.0.0','[]','["AZURE_RAI_POLICIES"]','[{"factKey":"guardrail.rai_custom_blocklist_count_configured","valueType":"NUMBER","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"guardrail.rai_custom_blocklist_count_configured","count_eq":0}','[{"key":"approvedBaseline","type":"STRING","defaultValue":"DEFAULT"}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"guardrail.rai_custom_blocklist_count_configured","count_eq":0}}}','{"immutable":true,"pass":{"approvedBaseline":"DEFAULT"},"fail":{"approvedBaseline":"STRICT"},"invalid":{}}','824fb6ddc4ceb24f64ea7126fd5c1fd31ce4c4f385843911c176f8f65cc7c1ac'),
('AGCF-AZR-015','1.0.0','[]','["AZURE_FOUNDRY_DEPLOYMENTS"]','[{"factKey":"model.name_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"model.publisher_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"not":{"fact":"model.name_configured","in":{"parameter":"approvedModelNames"}}},{"not":{"fact":"model.publisher_configured","in":{"parameter":"approvedModelPublishers"}}}]}','[{"key":"approvedModelNames","type":"STRING_LIST","defaultValue":[]},{"key":"approvedModelPublishers","type":"STRING_LIST","defaultValue":["Microsoft"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"not":{"fact":"model.name_configured","in":{"parameter":"approvedModelNames"}}},{"not":{"fact":"model.publisher_configured","in":{"parameter":"approvedModelPublishers"}}}]}}}','{"immutable":true,"pass":{"approvedModelNames":[],"approvedModelPublishers":["Microsoft"]},"fail":{"approvedModelNames":["CERTIFICATION_APPROVED_VALUE"],"approvedModelPublishers":[]},"invalid":{}}','c5f166554a75217d9a88f0c40e003415d53de20f9d26c83a7bd9d0c5a2fed28b'),
('AGCF-AZR-016','1.0.0','[]','["AZURE_FOUNDRY_DEPLOYMENTS"]','[{"factKey":"model.version_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"model.version_upgrade_option_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"not":{"fact":"model.version_configured","in":{"parameter":"approvedModelVersions"}}},{"not":{"fact":"model.version_upgrade_option_configured","in":{"parameter":"approvedUpgradeOptions"}}}]}','[{"key":"approvedModelVersions","type":"STRING_LIST","defaultValue":[]},{"key":"approvedUpgradeOptions","type":"STRING_LIST","defaultValue":["OnceNewDefaultVersionAvailable"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"not":{"fact":"model.version_configured","in":{"parameter":"approvedModelVersions"}}},{"not":{"fact":"model.version_upgrade_option_configured","in":{"parameter":"approvedUpgradeOptions"}}}]}}}','{"immutable":true,"pass":{"approvedModelVersions":[],"approvedUpgradeOptions":["OnceNewDefaultVersionAvailable"]},"fail":{"approvedModelVersions":["CERTIFICATION_APPROVED_VALUE"],"approvedUpgradeOptions":[]},"invalid":{}}','24c4c4bc1a384f0262cb19922b37969a39500d034c81419fdab7d5240c7db952'),
('AGCF-AZR-020','1.0.0','[]','["AZURE_FOUNDRY_MCP_SERVER"]','[{"factKey":"mcp.server_hostname_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"mcp.server_hostname_configured","in":{"parameter":"approvedMcpServerHosts"}}}','[{"key":"approvedMcpServerHosts","type":"STRING_LIST","defaultValue":[]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"mcp.server_hostname_configured","in":{"parameter":"approvedMcpServerHosts"}}}}}','{"immutable":true,"pass":{"approvedMcpServerHosts":[]},"fail":{"approvedMcpServerHosts":["CERTIFICATION_APPROVED_VALUE"]},"invalid":{}}','4fc7a03bdea5d625b1f2a5d3d220a8aae0e1fbbbeea6ea5eefc9e8d02a400463'),
('AGCF-AZR-021','1.0.0','[]','["AZURE_FOUNDRY_AGENT_TOOLS"]','[{"factKey":"agent.tool_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"agent.tool_type_configured","in":{"parameter":"approvedToolTypes"}}}','[{"key":"approvedToolTypes","type":"STRING_LIST","defaultValue":["function"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"agent.tool_type_configured","in":{"parameter":"approvedToolTypes"}}}}}','{"immutable":true,"pass":{"approvedToolTypes":["function"]},"fail":{"approvedToolTypes":[]},"invalid":{}}','523cb391b23892e2cd7c9b6527ee599aba9aa65179ffbe36278e541cd7747df7'),
('AGCF-AZR-023','1.0.0','[]','["AZURE_ML_ENDPOINTS"]','[{"factKey":"ml.endpoint_traffic_configured","valueType":"OBJECT","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"ml.endpoint_traffic_configured","empty":true}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"ml.endpoint_traffic_configured","empty":true}}}','null','2aabab97b65d3583e0ac807a7763593579d1b3691b49337287739c156415fa39'),
('AGCF-AZR-024','1.0.0','[]','["AZURE_ML_DEPLOYMENTS"]','[{"factKey":"compute.instance_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"ml.model_reference_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"not":{"fact":"compute.instance_type_configured","in":{"parameter":"approvedComputeTypes"}}},{"not":{"fact":"ml.model_reference_configured","in":{"parameter":"approvedModelReferences"}}}]}','[{"key":"approvedComputeTypes","type":"STRING_LIST","defaultValue":[]},{"key":"approvedModelReferences","type":"STRING_LIST","defaultValue":[]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"not":{"fact":"compute.instance_type_configured","in":{"parameter":"approvedComputeTypes"}}},{"not":{"fact":"ml.model_reference_configured","in":{"parameter":"approvedModelReferences"}}}]}}}','{"immutable":true,"pass":{"approvedComputeTypes":[],"approvedModelReferences":[]},"fail":{"approvedComputeTypes":["CERTIFICATION_APPROVED_VALUE"],"approvedModelReferences":["CERTIFICATION_APPROVED_VALUE"]},"invalid":{}}','1c3614803800182f0c0c3970255acf598377ff1bb27d940f6c1a71c1b83f6d69'),
('AGCF-AZR-029','1.0.0','[]','["AZURE_BOT_CHANNELS"]','[{"factKey":"bot.channel_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"bot.channel_type_configured","in":{"parameter":"approvedBotChannels"}}}','[{"key":"approvedBotChannels","type":"STRING_LIST","defaultValue":["DirectLineChannel"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"bot.channel_type_configured","in":{"parameter":"approvedBotChannels"}}}}}','{"immutable":true,"pass":{"approvedBotChannels":["DirectLineChannel"]},"fail":{"approvedBotChannels":[]},"invalid":{}}','eaaee3fb53602c297ed7c00903b04b6152ea28522340637866aed7380610feb9'),
('AGCF-AZR-030','1.0.0','[]','["AZURE_RBAC_GLOBAL"]','[{"factKey":"identity.assignment_scope_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"not":{"fact":"identity.assignment_scope_configured","in":{"parameter":"approvedAiResourceScopes"}}}','[{"key":"approvedAiResourceScopes","type":"STRING_LIST","defaultValue":[]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"not":{"fact":"identity.assignment_scope_configured","in":{"parameter":"approvedAiResourceScopes"}}}}}','{"immutable":true,"pass":{"approvedAiResourceScopes":[]},"fail":{"approvedAiResourceScopes":["CERTIFICATION_APPROVED_VALUE"]},"invalid":{}}','6a2168d5cdee58f3c619aa44e79f33c2b5231affe1b437c522f75b9cc9f07b5c'),
('AGCF-AZR-031','1.0.0','[]','["AZURE_RBAC_GLOBAL"]','[{"factKey":"identity.assignment_condition_version_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400},{"factKey":"identity.principal_type_configured","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"any":[{"fact":"identity.assignment_condition_version_configured","empty":true},{"not":{"fact":"identity.principal_type_configured","in":{"parameter":"approvedPrincipalTypes"}}}]}','[{"key":"approvedPrincipalTypes","type":"STRING_LIST","defaultValue":["ServicePrincipal","ManagedIdentity"]}]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"any":[{"fact":"identity.assignment_condition_version_configured","empty":true},{"not":{"fact":"identity.principal_type_configured","in":{"parameter":"approvedPrincipalTypes"}}}]}}}','{"immutable":true,"pass":{"approvedPrincipalTypes":["ServicePrincipal","ManagedIdentity"]},"fail":{"approvedPrincipalTypes":[]},"invalid":{}}','475688f924989d71aff5f557ae858420e20010eef2fe8aed511f5db22d7cee48'),
('AGCF-AZR-032','1.0.0','[]','["AZURE_STORAGE_ACCOUNTS","AZURE_ONELAKE_STORES"]','[{"factKey":"data.source_sensitivity","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]','{"fact":"data.source_sensitivity","in":["NOT_SCANNED"]}','[]','{"mode":"ARTIFACT_FACTS","artifactFacts":{"predicate":{"fact":"data.source_sensitivity","in":["NOT_SCANNED"]}}}','null','58397bf0b4116151313c3f943118feafc9130f6be0f75a67364fedff69480a26')
)
UPDATE platform.ai_grid_policy_versions policy
   SET artifact_types_json = corrections.artifact_types_json::jsonb,
       native_kinds_json = corrections.native_kinds_json::jsonb,
       required_facts_json = corrections.required_facts_json::jsonb,
       predicate_json = corrections.predicate_json::jsonb,
       parameter_definitions_json = corrections.parameter_definitions_json::jsonb,
       evaluation_mode = 'ARTIFACT_FACTS',
       evaluation_definition_json = corrections.evaluation_definition_json::jsonb,
       certification_parameter_profile_json = corrections.certification_parameter_profile_json::jsonb,
       package_digest = corrections.package_digest
  FROM corrections
 WHERE policy.policy_id = corrections.policy_id
   AND policy.version = corrections.version
   AND policy.lifecycle = 'VALIDATED';


-- source: V90__ai_grid_phase_1_private_preview_governance.sql
-- Private customer-validation governance is deliberately separate from the
-- seven-gate GA release board.  Policy rows remain unavailable until the
-- preview controls record an explicit, all-or-nothing admission decision.
CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_preview_release (
    release_family varchar(64) PRIMARY KEY,
    manifest_digest varchar(64) NOT NULL,
    total_policies integer NOT NULL,
    state varchar(32) NOT NULL DEFAULT 'PAUSED',
    internal_tenant_id uuid,
    approved_cohort_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_approved_cohort_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    approved_by varchar(255),
    approved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (state IN ('PAUSED','READY','PROMOTED','INVALIDATED')),
    CHECK (jsonb_typeof(approved_cohort_json) = 'array'),
    CHECK (jsonb_typeof(last_approved_cohort_json) = 'array')
);

CREATE TABLE IF NOT EXISTS platform.ai_grid_phase_1_preview_gate_evidence (
    gate_key varchar(64) PRIMARY KEY,
    status varchar(16) NOT NULL DEFAULT 'PENDING',
    evidence_ref varchar(1024),
    results_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    recorded_by varchar(255),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status IN ('PENDING','PASSED','FAILED')),
    CHECK (jsonb_typeof(results_json) = 'object')
);

INSERT INTO platform.ai_grid_phase_1_preview_release
    (release_family, manifest_digest, total_policies)
SELECT 'AGCF_PHASE_1',
       md5(string_agg(coalesce(package_digest, ''), ',' ORDER BY policy_id, version)),
       count(*)
  FROM platform.ai_grid_policy_versions
 WHERE release_family = 'AGCF_PHASE_1';

INSERT INTO platform.ai_grid_phase_1_preview_gate_evidence (gate_key)
VALUES
    ('CATALOG_BROWSER_E2E'),
    ('CERTIFICATION_246'),
    ('SECURITY_SMOKE'),
    ('PERFORMANCE_SMOKE'),
    ('ROLLBACK_SMOKE'),
    ('INTERNAL_CANARY')
ON CONFLICT (gate_key) DO NOTHING;

-- Any package-digest change invalidates a previous private-preview decision.
CREATE OR REPLACE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.release_family = 'AGCF_PHASE_1'
       AND NEW.release_family = 'AGCF_PHASE_1'
       AND coalesce(OLD.package_digest, '') <> coalesce(NEW.package_digest, '') THEN
        UPDATE platform.ai_grid_phase_1_preview_release
           SET state = 'INVALIDATED', approved_cohort_json = '[]'::jsonb,
               updated_at = now()
         WHERE release_family = 'AGCF_PHASE_1';
        UPDATE platform.ai_grid_policy_distribution
           SET available = false, rollout_stage = 'PAUSED',
               canary_tenant_ids_json = '[]'::jsonb, updated_at = now()
         WHERE policy_id = NEW.policy_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ai_grid_phase_1_preview_digest_change
    ON platform.ai_grid_policy_versions;
CREATE TRIGGER trg_ai_grid_phase_1_preview_digest_change
AFTER UPDATE OF package_digest ON platform.ai_grid_policy_versions
FOR EACH ROW EXECUTE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change();


-- source: V91__ai_grid_out_of_box_policy_shipping.sql
-- Phase 1 shipping is source-controlled.  Tenant evidence is deliberately not
-- consulted while installing, publishing, distributing, or pinning a package.

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_rollouts (
    id uuid PRIMARY KEY,
    release_id varchar(128) NOT NULL,
    release_type varchar(64) NOT NULL,
    policy_id varchar(128) NOT NULL,
    previous_version varchar(32),
    new_version varchar(32) NOT NULL,
    package_digest varchar(64) NOT NULL,
    distribution_snapshot_json jsonb NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'PENDING',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    UNIQUE (release_id, policy_id, new_version),
    CHECK (release_type IN ('INITIAL_CATALOG','POLICY_VERSION','REPLACEMENT')),
    CHECK (status IN ('PENDING','PROCESSING','COMPLETED','FAILED'))
);

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_rollout_tasks (
    id uuid PRIMARY KEY,
    rollout_id uuid NOT NULL REFERENCES platform.ai_grid_policy_rollouts(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    status varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz,
    source_snapshot_run_id uuid,
    assessment_run_id uuid,
    failure_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (rollout_id, tenant_id),
    CHECK (status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','COMPLETED','FAILED'))
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_rollout_tasks_claim
    ON platform.ai_grid_policy_rollout_tasks (status, next_retry_at, created_at);

-- Promote every bundled AGCF package. V76/V88/V89 remain immutable; V91 is the
-- reviewed forward-only shipping decision and pins distribution to its digest.
UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'PUBLISHED',
       approved_by = coalesce(approved_by, 'ai-grid-package-compiler'),
       approved_at = coalesce(approved_at, now()),
       published_at = coalesce(published_at, now())
 WHERE policy_id LIKE 'AGCF-%'
   AND package_source_ref LIKE 'policy-packages/agcf/%'
   AND lifecycle IN ('DRAFT','VALIDATED');

UPDATE platform.ai_grid_policy_versions SET default_selection = 'ENABLED'
 WHERE policy_id LIKE 'AGCF-%' AND default_selection = 'PREVIEW';

-- generated-manifest-digest-bindings:start
-- Generated by scripts/compile-ai-grid-phase1.mjs. Do not hand-edit package rows.
WITH shipped(policy_id,version,package_digest) AS (VALUES
('AGCF-AWS-001','1.0.0','57781735b507f8f284472af507020181380e71ae41716fd70ba84a904e2697b1'),
('AGCF-AWS-002','1.0.0','c12b96252a146d3e49dfb137130bf02888d2aafd01490fb94cf97f72e30b6a2a'),
('AGCF-AWS-003','1.0.0','9feb9672faee1c0cbac3301be20f69bfde67b30cd8373932260fe36404e32487'),
('AGCF-AWS-004','1.0.0','07cd28465e7064470b624fb880f668fb85d1378748ecc5c7170e84a4f342d09f'),
('AGCF-AWS-005','1.0.0','23b8b88e1f39b1027b06523d80f50a0d04c561a70c20892935f3de39f08c590d'),
('AGCF-AWS-006','1.0.0','7bb3c448e05ef599a309356a41c30bbd6840754861453cf7cf1919d61d121c2d'),
('AGCF-AWS-007','1.0.0','5c190b1ba579381d98752ed9bfe778ee72726f322a33ea9ae746ae4d2c666586'),
('AGCF-AWS-008','1.0.0','a1ca007efa0d57ff15657a8c0f5e319cf29e3594083f7b25ff53f1305652ee67'),
('AGCF-AWS-009','1.0.0','b0e9bd0238a1a76adb5962d9a50752c9d00df4c753b351ebcf37123500f79a6c'),
('AGCF-AWS-010','1.0.0','2085139054fde1a89dd39349c5246be8659b3f86e16e5df8bd2c879da5d4c02e'),
('AGCF-AWS-011','1.0.0','9ca94d96b62255aff0b50627bce8a40a93b8958b1a28868c29eab35127d480da'),
('AGCF-AWS-012','1.0.0','07cc0a7ce59e1691a3b05fb5b35ef25533a91dda201a96423108429edbea5d40'),
('AGCF-AWS-013','1.0.0','ad4f6868de61f569dc70460d3c146a948aee1191c660cc189800d546f02cdd3c'),
('AGCF-AWS-014','1.0.0','7dcf639821e689065acde25d6ee6e641b80e01eb473f03b6d4ef11ae65b623c0'),
('AGCF-AWS-015','1.0.0','e9a5a7eed7500f691aec17b5ef623e0e6dfdac7c55c3e54c01f93633c930b84a'),
('AGCF-AWS-016','1.0.0','63b237f362088e6e18fe80b313c6a2d0f8cbe1c8b72f7b0d523251097e822d75'),
('AGCF-AWS-017','1.0.0','92032a2275adb81da31144fba77922b2466e398dece88862760f29b84911c799'),
('AGCF-AWS-018','1.0.0','33027bed112f7fb9e19f2f532c04a7996dc105c76b9aa931e859d72aa797b927'),
('AGCF-AWS-019','1.0.0','c8ce30888a018c8442570d5cc4f803285682a6cf8bd81886a30fa13172c7edcd'),
('AGCF-AWS-020','1.0.0','5600cba4b91ce8eb887aa61252cd19620274a3818f3df6ac9c5338b88dde04ed'),
('AGCF-AWS-021','1.0.0','a2f3b5aa79d35ca337633c73ecb65635ce29f2feba47945ed63449f4408e1391'),
('AGCF-AWS-022','1.0.0','17b466fce5a0933cd2f29a16ba150570968b5bd7bdbb7c100fe9247c53b3effe'),
('AGCF-AWS-023','1.0.0','46bd7553eb526bbdc0020e2471c68d8e708897765a5a680e923790778db323b6'),
('AGCF-AWS-024','1.0.0','32493d9bac26e8c6392bc9e0be84bb475257836e4b95e8cb3a33b435bd483a69'),
('AGCF-AWS-025','1.0.0','8d45578380aee8ad28aa11817b4fac1e767322c216a0c25b859d95bd12910c34'),
('AGCF-AWS-026','1.0.0','00f9dbf74b2df8503837a8d898285bbb83ef77008ef19f449d0f32ab47d81e81'),
('AGCF-AWS-027','1.0.0','60357eaee299c5f144c7c9979655d44f81fae435acf0b218186aa5045ab4a331'),
('AGCF-AWS-028','1.0.0','7790daf45be65ae53c8e236df812d4015709b651405a3103726017662f775153'),
('AGCF-AWS-029','1.0.0','c0591f1280f470e380698f3ad97e4162b314d3eff20988f819d57be51f76e429'),
('AGCF-AWS-030','1.0.0','136d320464e1b73b69caa7aefebd72e73caf94328c986bc78fc66cf7813a09ae'),
('AGCF-AWS-031','1.0.0','2a234e76ad25868156e3292f6c599149fbefd375585273e6b5d8fc7c2c75fe55'),
('AGCF-AWS-032','1.0.0','cd0298bd26d3ae64f730b55da8ccccdcd4a4cdb81ef4913b8e775b1f9f25f202'),
('AGCF-AWS-033','1.0.0','9723cada991dc4c9de96f16e50e67fd13b320f5d61294c96a7fa11d45b5fe382'),
('AGCF-AWS-034','1.0.0','468d4f2f64d16d755e2268d4817e3743b40bdbec76ed2ff447b2482c88d3ee24'),
('AGCF-AWS-035','1.0.0','d4b365402012676f0a0250ba30c6570a2b6ecb1dbe4b3c460e123fad162313cf'),
('AGCF-AWS-036','1.0.0','fc02fa9441435d43ae05ac28673c413059567c4eb3106fec0fe0e5230b0ff9c2'),
('AGCF-AWS-037','1.0.0','eb83fa2afdb801fd67a1cf37c3b6214be2b19774e3abd06ca146ed3315739c21'),
('AGCF-AWS-038','1.0.0','377f6069bef60525f43d1fe5bda8ff8d5cde4334fd355937a58378efaa371967'),
('AGCF-AZR-001','1.0.0','046bbffeaa50c65541cdb7742dcf4ced919d025579045d2007af0d84092704e2'),
('AGCF-AZR-002','1.0.0','6439276140620f364748a6c4dff16c7f68c4fa8934336fa3b0c0686c0f481608'),
('AGCF-AZR-003','1.0.0','df812e74b06ec3d28df42cccd2c4e6394a03e8650a76b24ce1a12cfe016eb47d'),
('AGCF-AZR-004','1.0.0','7cdc37529db58523b5fbe9c8bf7a8b1c77884d147533ba8c384c623b51d4bcc1'),
('AGCF-AZR-005','1.0.0','bedc94b31e40aa4f55664b99b7dacacd73667a482068f3e36e2daf01bfb54aaf'),
('AGCF-AZR-006','1.0.0','2af6dcd38095ab9090be5ff78990ccf8afba8042ea693603eaa08083f46dfd3b'),
('AGCF-AZR-007','1.0.0','10f2a258b173eb96c6f05e9b63fafbe4dd5dd3db8bf3a52bfdac51e8fb62e593'),
('AGCF-AZR-008','1.0.0','ece3b78208cfaae29c247c8ff78a1554f387b1c94d8617ad59677f64d2e5f2fb'),
('AGCF-AZR-009','1.0.0','98eb727f433b21c7bbb7966cd8c7a3bd384ad692845fbe6775e9b1fe264b6e7b'),
('AGCF-AZR-010','1.0.0','a54b33061982f59777b5aa68c4ed9f7b06b960eaf56eee683e4afe5e317c5dea'),
('AGCF-AZR-011','1.0.0','065cf0952abfc7d4a84f26f7e9a353fcf52d5451d9d09c4355c710fae4d49bc6'),
('AGCF-AZR-012','1.0.0','664aca53cd6c3ed7f437dfa42cca2372280a3066797a9a4fba7c98c8cd45f79a'),
('AGCF-AZR-013','1.0.0','9e824a72c65ea1ba5c97d77caa043cef4da26951a62f5bc5716669f4f50ff4d5'),
('AGCF-AZR-014','1.0.0','c17014f0ca16723456cc795d8b04c52f784298d79f1f3254837b39e1c341c16e'),
('AGCF-AZR-015','1.0.0','52a3ebeb4e58935dc7b1a6b5837b1319bf26d98d4c9c1532cc2ccf84ab06450c'),
('AGCF-AZR-016','1.0.0','3071eec263ebb4a9d468da373cd2d7d6aa2d80925277828f7ac069de7fc72a4f'),
('AGCF-AZR-017','1.0.0','2616adf6abb03e4fcf61349130285dceb34122f2198da2ca35f52ac254f39359'),
('AGCF-AZR-018','1.0.0','999807ed8ca6bd7ba48349624be80bb44b4ea70e33a9c6a8f12ebff3550e7184'),
('AGCF-AZR-019','1.0.0','d444cf2eabef606ab116a7bab9dd4f112b8c3e7f91d31e90151540f3badecc4b'),
('AGCF-AZR-020','1.0.0','055a6129236c68ef0997e2486d3b1aed1ca25be2fe376167ea34e4d9a6afb97a'),
('AGCF-AZR-021','1.0.0','e4e301f70db0173986a0064c08067a528c8956e2703697e6f6101760c5492250'),
('AGCF-AZR-022','1.0.0','5ed0d2f2958c4c71f29e16601ef01bebf77ae8905f0f42954c64d0025d832108'),
('AGCF-AZR-023','1.0.0','e50b5f26ed18870f2723e9ea177effab94e25cbf0dad9f501c386ae5b10a075f'),
('AGCF-AZR-024','1.0.0','74d0fd1107a27fbee282e4fe9a2e2b99977668adc79715b277ca0ca6abf1520a'),
('AGCF-AZR-025','1.0.0','ca67ac614ec02a61f27d2bb4118bd51f0132c5f662421b22825612006b7e87c8'),
('AGCF-AZR-026','1.0.0','534500676194bbde05c1c2071fb22612c101a7b7994f6f8a1c793754a854810c'),
('AGCF-AZR-027','1.0.0','31946f2b9733f78d7a02865edf162a74ef6c295e9adf19832466e9981c3bb833'),
('AGCF-AZR-028','1.0.0','a1b5d9432ee0554b15446b519ceefc2100e4010fb0b2cb82f615fef949061233'),
('AGCF-AZR-029','1.0.0','e484838e945bd0df97f75305668091f5397e4f39f6a991505513a6ba43f92884'),
('AGCF-AZR-030','1.0.0','114068db61bb49bcbee8f502f4608b8b384b6dd7336cdbf679cd6464eb24fb95'),
('AGCF-AZR-031','1.0.0','9bcaf2cc4a18af2a5f7d9234c5ba8606a12b27eda294d10220cdd3dc8db272a1'),
('AGCF-AZR-032','1.0.0','0f05267df3a5c72b4210721794a71b91560e321c3bce4c12926cad6aed51e62c'),
('AGCF-XSP-001','1.0.0','e94674a32c10d0c6002826434944f523f1e1180139134b4be21e5a34f1ccfa9a'),
('AGCF-XSP-002','1.0.0','c5924043d588c67f2031ac30ebe4df12f9b569ed35815fd3f8bc3f2e9e687fc2'),
('AGCF-XSP-003','1.0.0','dc97f04ed54742f22c6508c48895137b030a4dbcd5bd1b9ba62ee841b53876db'),
('AGCF-XSP-004','1.0.0','10d8195e99d426cfd7e7de6205af391fb95aed50c2136efeacf4ac6054be909d'),
('AGCF-XSP-005','1.0.0','c91296a7958e37a3d29f78d08304b5310d06f9cb8883ef35851e2b44da4d75bc'),
('AGCF-XSP-006','1.0.0','d7907c4de2724d819152f823c92799c27d7bc977b79bd23fe4f2fa43f41162c1')
)
UPDATE platform.ai_grid_policy_versions policy
   SET package_digest = shipped.package_digest
  FROM shipped
 WHERE policy.policy_id = shipped.policy_id
   AND policy.version = shipped.version
   AND policy.package_source_ref LIKE 'policy-packages/agcf/%';
-- generated-manifest-digest-bindings:end

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id, available, default_selection, rollout_stage, canary_tenant_ids_json, pinned_version, updated_by)
SELECT p.policy_id, true, p.default_selection, 'GENERAL_AVAILABILITY', '[]'::jsonb, p.version,
       'ai-grid-package-compiler'
  FROM platform.ai_grid_policy_versions p
 WHERE p.policy_id LIKE 'AGCF-%'
   AND p.package_source_ref LIKE 'policy-packages/agcf/%'
   AND p.lifecycle = 'PUBLISHED'
ON CONFLICT (policy_id) DO UPDATE
   SET available = true,
       default_selection = excluded.default_selection,
       rollout_stage = 'GENERAL_AVAILABILITY',
       canary_tenant_ids_json = '[]'::jsonb,
       pinned_version = excluded.pinned_version,
       updated_by = excluded.updated_by,
       updated_at = now();

INSERT INTO platform.ai_grid_policy_rollouts
    (id, release_id, release_type, policy_id, previous_version, new_version, package_digest, distribution_snapshot_json, status, completed_at)
SELECT md5('AGCF_PHASE_1_INITIAL:' || p.policy_id || ':' || p.version)::uuid,
       'AGCF_PHASE_1_INITIAL', 'INITIAL_CATALOG', p.policy_id, null, p.version, p.package_digest,
       jsonb_build_object('available', d.available, 'defaultSelection', d.default_selection,
                          'rolloutStage', d.rollout_stage, 'canaryTenantIds', d.canary_tenant_ids_json,
                          'pinnedVersion', d.pinned_version),
       'PENDING', null
  FROM platform.ai_grid_policy_versions p
  JOIN platform.ai_grid_policy_distribution d ON d.policy_id = p.policy_id
 WHERE p.policy_id LIKE 'AGCF-%'
   AND p.package_source_ref LIKE 'policy-packages/agcf/%'
   AND p.lifecycle = 'PUBLISHED'
ON CONFLICT (release_id, policy_id, new_version) DO NOTHING;

INSERT INTO platform.ai_grid_policy_rollout_tasks (id, rollout_id, tenant_id)
SELECT md5(r.id::text || ':' || t.id::text)::uuid, r.id, t.id
  FROM platform.ai_grid_policy_rollouts r
 CROSS JOIN platform.tenants t
 WHERE r.release_id = 'AGCF_PHASE_1_INITIAL'
   AND t.status = 'ACTIVE' AND t.deleted_at IS NULL
ON CONFLICT (rollout_id, tenant_id) DO NOTHING;


-- source: V92__revoke_automatic_ai_grid_policy_publishing.sql
-- V91 installed the reviewed package bytes but also promoted every package to
-- PUBLISHED and made it generally available.  Installation must not constitute
-- approval or tenant distribution: those actions remain explicit governance
-- operations.

UPDATE platform.ai_grid_policy_versions
   SET lifecycle = 'VALIDATED',
       approved_by = NULL,
       approved_at = NULL,
       published_at = NULL
 WHERE policy_id LIKE 'AGCF-%'
   AND package_source_ref LIKE 'policy-packages/agcf/%'
   AND lifecycle = 'PUBLISHED'
   AND approved_by = 'ai-grid-package-compiler';

UPDATE platform.ai_grid_policy_distribution
   SET available = false,
       rollout_stage = 'PAUSED',
       canary_tenant_ids_json = '[]'::jsonb,
       pinned_version = NULL,
       updated_by = 'ai-grid-shipping-correction',
       updated_at = now()
 WHERE policy_id LIKE 'AGCF-%'
   AND updated_by = 'ai-grid-package-compiler';


-- source: V93__cancel_automatic_ai_grid_policy_rollouts.sql
-- Preserve the V91 rollout audit records, but prevent its automatically-created
-- tenant work from being claimed after package installation is separated from
-- publication and distribution.

ALTER TABLE platform.ai_grid_policy_rollouts
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollouts_status_check;
ALTER TABLE platform.ai_grid_policy_rollouts
    ADD CONSTRAINT ai_grid_policy_rollouts_status_check
    CHECK (status IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELLED'));

ALTER TABLE platform.ai_grid_policy_rollout_tasks
    DROP CONSTRAINT IF EXISTS ai_grid_policy_rollout_tasks_status_check;
ALTER TABLE platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_status_check
    CHECK (status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','COMPLETED','FAILED','CANCELLED'));

UPDATE platform.ai_grid_policy_rollout_tasks task
   SET status = 'CANCELLED',
       failure_detail = 'Cancelled: package installation does not authorize tenant rollout',
       next_retry_at = NULL,
       completed_at = now(),
       updated_at = now()
  FROM platform.ai_grid_policy_rollouts rollout
 WHERE task.rollout_id = rollout.id
   AND rollout.release_id = 'AGCF_PHASE_1_INITIAL'
   AND task.status IN ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','FAILED');

UPDATE platform.ai_grid_policy_rollouts rollout
   SET status = 'CANCELLED', completed_at = now()
 WHERE rollout.release_id = 'AGCF_PHASE_1_INITIAL'
   AND status <> 'COMPLETED';


-- source: V94__ai_grid_policy_id_replacement_lifecycle.sql
-- Phase 2 policy identity is replacement-based: a deprecated policy keeps its
-- audit history but can never be selected or evaluated again.

-- Some pre-V76 installations already contained the Phase 1 policy IDs.  The
-- original seed correctly avoided replacing them, but left their release
-- metadata/distribution rows absent.  Normalize that historical path without
-- publishing anything: package installation remains VALIDATED and PAUSED.
UPDATE platform.ai_grid_policy_versions
   SET release_family = coalesce(release_family, 'AGCF_PHASE_1'),
       release_wave = coalesce(release_wave, 'PHASE_1')
 WHERE policy_id LIKE 'AGCF-%';

INSERT INTO platform.ai_grid_policy_distribution
    (policy_id, available, default_selection, rollout_stage, canary_tenant_ids_json, pinned_version, updated_by)
SELECT p.policy_id, false, p.default_selection, 'PAUSED', '[]'::jsonb, null,
       'ai-grid-lifecycle-normalization'
  FROM platform.ai_grid_policy_versions p
 WHERE p.policy_id LIKE 'AGCF-%'
ON CONFLICT (policy_id) DO NOTHING;

ALTER TABLE platform.ai_grid_policy_versions
    DROP CONSTRAINT IF EXISTS ai_grid_policy_versions_lifecycle_check;
ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_versions_lifecycle_check
    CHECK (lifecycle IN ('DRAFT','VALIDATED','APPROVED','CANARY','PUBLISHED','RETIRED','DEPRECATED'));

ALTER TABLE platform.ai_grid_policy_release_decisions
    ADD COLUMN IF NOT EXISTS approved_package_digest varchar(128);

CREATE OR REPLACE FUNCTION platform.ai_grid_policy_release_decisions_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'AI Grid policy release decisions are immutable';
END;
$$;

DROP TRIGGER IF EXISTS ai_grid_policy_release_decisions_immutable
    ON platform.ai_grid_policy_release_decisions;
CREATE TRIGGER ai_grid_policy_release_decisions_immutable
    BEFORE UPDATE OR DELETE ON platform.ai_grid_policy_release_decisions
    FOR EACH ROW EXECUTE FUNCTION platform.ai_grid_policy_release_decisions_immutable();

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_release_bindings (
    id uuid PRIMARY KEY,
    approval_decision_id uuid NOT NULL UNIQUE REFERENCES platform.ai_grid_policy_release_decisions(id),
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    approved_package_digest varchar(128) NOT NULL,
    distribution_snapshot_json jsonb NOT NULL,
    target_tenant_ids_json jsonb NOT NULL,
    bound_by varchar(255) NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT now(),
    state varchar(32) NOT NULL DEFAULT 'ACTIVE',
    revoked_at timestamptz,
    revoked_by varchar(255),
    revocation_reason text,
    CHECK (state IN ('ACTIVE','REVOKED','CANCELLED')),
    CHECK ((state = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL)
        OR (state <> 'ACTIVE' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
    UNIQUE (policy_id, policy_version, approved_package_digest)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_release_bindings_active
    ON platform.ai_grid_policy_release_bindings (policy_id, policy_version)
    WHERE state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_deprecations (
    id uuid PRIMARY KEY,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    reason text NOT NULL,
    successor_policy_id varchar(128),
    deprecated_by varchar(255) NOT NULL,
    deprecated_at timestamptz NOT NULL DEFAULT now(),
    idempotency_key varchar(128) NOT NULL,
    UNIQUE (policy_id, policy_version),
    UNIQUE (idempotency_key)
);

CREATE TABLE IF NOT EXISTS platform.ai_grid_policy_deprecation_tasks (
    id uuid PRIMARY KEY,
    deprecation_id uuid NOT NULL REFERENCES platform.ai_grid_policy_deprecations(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    state varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz,
    failure_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (deprecation_id, tenant_id),
    CHECK (state IN ('PENDING','PROCESSING','COMPLETED','FAILED','CANCELLED'))
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_deprecation_tasks_claim
    ON platform.ai_grid_policy_deprecation_tasks (state, next_retry_at, created_at);


-- source: V95__add_policy_distribution_release_binding_columns.sql
-- The governed catalog and tenant policy reads use the approved package digest
-- and the immutable release-decision ID carried by each distribution row.  The
-- service began reading these fields before the distribution table migration
-- declared them, which made catalog requests fail with an undefined-column SQL
-- error on every migrated database.
ALTER TABLE platform.ai_grid_policy_distribution
    ADD COLUMN IF NOT EXISTS approved_package_digest varchar(128),
    ADD COLUMN IF NOT EXISTS release_decision_id uuid
        REFERENCES platform.ai_grid_policy_release_decisions(id);

ALTER TABLE platform.ai_grid_policy_distribution
    DROP CONSTRAINT IF EXISTS ai_grid_policy_distribution_release_binding_check;

ALTER TABLE platform.ai_grid_policy_distribution
    ADD CONSTRAINT ai_grid_policy_distribution_release_binding_check
    CHECK (
        (approved_package_digest IS NULL AND release_decision_id IS NULL)
        OR (approved_package_digest IS NOT NULL AND release_decision_id IS NOT NULL)
    );


-- The packaged catalog is the sole source of the tenant target version.
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version DROP DEFAULT;
