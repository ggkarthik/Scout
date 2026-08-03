-- migration-guard: platform-only
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
