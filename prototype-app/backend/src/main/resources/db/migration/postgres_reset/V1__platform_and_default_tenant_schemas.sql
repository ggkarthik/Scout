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

CREATE TABLE IF NOT EXISTS tenant_default.sync_runs (
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
