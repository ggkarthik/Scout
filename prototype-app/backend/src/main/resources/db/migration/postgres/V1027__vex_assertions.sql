CREATE TABLE IF NOT EXISTS vex_assertions (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities(id),
    observation_id uuid REFERENCES vulnerability_intel_observations(id),
    target_id uuid NOT NULL REFERENCES vulnerability_targets(id),
    software_identity_id uuid REFERENCES software_identities(id),
    cpe_id uuid REFERENCES cpe_dim(id),
    source_system character varying(80) NOT NULL,
    provider character varying(120) NOT NULL,
    document_id character varying(255) NOT NULL,
    statement_key character varying(512) NOT NULL,
    status character varying(64) NOT NULL,
    trust_tier character varying(40) NOT NULL,
    freshness character varying(40) NOT NULL,
    ecosystem character varying(120),
    namespace character varying(120),
    package_name character varying(220),
    normalized_product_key character varying(500) NOT NULL,
    version_exact character varying(255),
    version_start character varying(255),
    start_inclusive boolean,
    version_end character varying(255),
    end_inclusive boolean,
    fixed_version character varying(255),
    raw_target text,
    evidence_json text,
    published_at timestamp(6) with time zone,
    last_seen_at timestamp(6) with time zone NOT NULL,
    created_at timestamp(6) with time zone NOT NULL,
    updated_at timestamp(6) with time zone NOT NULL,
    CONSTRAINT uk_vex_assertions_target UNIQUE (target_id),
    CONSTRAINT uk_vex_assertions_statement UNIQUE (vulnerability_id, source_system, document_id, statement_key)
);

CREATE INDEX IF NOT EXISTS idx_vex_assertions_vulnerability ON vex_assertions(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_source ON vex_assertions(source_system);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_target ON vex_assertions(target_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_identity ON vex_assertions(software_identity_id);
CREATE INDEX IF NOT EXISTS idx_vex_assertions_cpe ON vex_assertions(cpe_id);

ALTER TABLE IF EXISTS component_vulnerability_states
    ADD COLUMN IF NOT EXISTS matched_vex_assertion_id uuid REFERENCES vex_assertions(id);

CREATE INDEX IF NOT EXISTS idx_comp_vuln_state_vex_assertion
    ON component_vulnerability_states(matched_vex_assertion_id);

ALTER TABLE IF EXISTS findings
    ADD COLUMN IF NOT EXISTS matched_vex_assertion_id uuid REFERENCES vex_assertions(id);

CREATE INDEX IF NOT EXISTS idx_findings_vex_assertion
    ON findings(matched_vex_assertion_id);
