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
