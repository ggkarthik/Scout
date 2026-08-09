-- migration-guard: platform-only
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
