-- migration-guard: tenant-only
-- Generated from a disposable fully migrated tenant schema; no runtime data.
-- PostgreSQL database dump
--


-- Dumped from database version 17.9 (Homebrew)
-- Dumped by pg_dump version 17.9 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: ${tenantSchema}; Type: SCHEMA; Schema: -; Owner: -
--



SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ai_grid_artifact_classifications; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_artifact_classifications (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    artifact_id uuid NOT NULL,
    technology_id character varying(128) NOT NULL,
    capability character varying(128),
    primary_technology boolean DEFAULT false NOT NULL,
    state character varying(32) NOT NULL,
    registry_version character varying(32) NOT NULL,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    classified_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_artifact_classifications FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_assessments; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_assessments (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    subject_type character varying(32) NOT NULL,
    subject_id uuid NOT NULL,
    snapshot_manifest_id uuid,
    selection character varying(32) NOT NULL,
    applicability character varying(32) NOT NULL,
    evidence_readiness character varying(32) NOT NULL,
    decision character varying(32) NOT NULL,
    reason_code character varying(128) NOT NULL,
    missing_evidence_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    input_facts_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    fingerprint character varying(64) NOT NULL,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL,
    evaluation_as_of timestamp with time zone NOT NULL,
    decision_fingerprint character varying(64)
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_assessments FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_budget_admissions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_budget_admissions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    resource_families_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    decision character varying(32) NOT NULL,
    reason_code character varying(64) NOT NULL,
    usage_json jsonb NOT NULL,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL,
    environment character varying(64) DEFAULT '*'::character varying NOT NULL,
    criticality character varying(32) DEFAULT '*'::character varying NOT NULL,
    CONSTRAINT ai_grid_budget_admissions_decision_check CHECK (((decision)::text = ANY ((ARRAY['ADMITTED'::character varying, 'THROTTLED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_admissions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_budget_alerts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_budget_alerts (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid,
    metric character varying(64) NOT NULL,
    level character varying(32) NOT NULL,
    observed_value bigint NOT NULL,
    limit_value bigint NOT NULL,
    status character varying(32) DEFAULT 'OPEN'::character varying NOT NULL,
    first_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_by character varying(255),
    acknowledged_at timestamp with time zone,
    CONSTRAINT ai_grid_budget_alerts_level_check CHECK (((level)::text = ANY ((ARRAY['WARNING'::character varying, 'EXCEEDED'::character varying])::text[]))),
    CONSTRAINT ai_grid_budget_alerts_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'ACKNOWLEDGED'::character varying, 'RESOLVED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_alerts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_budget_config; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_budget_config (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    enforcement_mode character varying(32) DEFAULT 'OBSERVE'::character varying NOT NULL,
    daily_scan_limit bigint,
    daily_provider_api_call_limit bigint,
    daily_new_snapshot_bytes_limit bigint,
    daily_processing_ms_limit bigint,
    retained_snapshot_bytes_limit bigint,
    warning_ratio double precision DEFAULT 0.80 NOT NULL,
    updated_by character varying(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_budget_config_daily_new_snapshot_bytes_limit_check CHECK (((daily_new_snapshot_bytes_limit IS NULL) OR (daily_new_snapshot_bytes_limit > 0))),
    CONSTRAINT ai_grid_budget_config_daily_processing_ms_limit_check CHECK (((daily_processing_ms_limit IS NULL) OR (daily_processing_ms_limit > 0))),
    CONSTRAINT ai_grid_budget_config_daily_provider_api_call_limit_check CHECK (((daily_provider_api_call_limit IS NULL) OR (daily_provider_api_call_limit > 0))),
    CONSTRAINT ai_grid_budget_config_daily_scan_limit_check CHECK (((daily_scan_limit IS NULL) OR (daily_scan_limit > 0))),
    CONSTRAINT ai_grid_budget_config_enforcement_mode_check CHECK (((enforcement_mode)::text = ANY ((ARRAY['OBSERVE'::character varying, 'THROTTLE'::character varying])::text[]))),
    CONSTRAINT ai_grid_budget_config_retained_snapshot_bytes_limit_check CHECK (((retained_snapshot_bytes_limit IS NULL) OR (retained_snapshot_bytes_limit > 0))),
    CONSTRAINT ai_grid_budget_config_warning_ratio_check CHECK (((warning_ratio > (0)::double precision) AND (warning_ratio < (1)::double precision)))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_config FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_capability_observations; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_capability_observations (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    capability_id character varying(128) NOT NULL,
    connector character varying(128) NOT NULL,
    account_id character varying(255) NOT NULL,
    region character varying(128) NOT NULL,
    resource_family character varying(128) NOT NULL,
    connector_version character varying(64),
    observed_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    status character varying(32) NOT NULL,
    detail text,
    CONSTRAINT ai_grid_capability_observations_status_check CHECK (((status)::text = ANY ((ARRAY['COMPLETE'::character varying, 'DISABLED'::character varying, 'UNAUTHORIZED'::character varying, 'UNSUPPORTED_API'::character varying, 'PARTIAL'::character varying, 'ERROR'::character varying, 'STALE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_capability_observations FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_coverage_gaps; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_coverage_gaps (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    fingerprint character varying(64) NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid,
    policy_id character varying(128),
    state character varying(64) NOT NULL,
    reason text NOT NULL,
    required_action text,
    status character varying(32) DEFAULT 'OPEN'::character varying NOT NULL,
    first_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    coverage_epoch_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_coverage_gaps FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_current_coverage_artifacts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_current_coverage_artifacts (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    epoch_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    account_id character varying(64) NOT NULL,
    region character varying(64) NOT NULL,
    resource_family character varying(128) NOT NULL,
    artifact_type character varying(64) NOT NULL,
    native_kind character varying(128) NOT NULL,
    technology_id character varying(128) DEFAULT 'UNCLASSIFIED'::character varying NOT NULL,
    environment character varying(64) DEFAULT 'UNSPECIFIED'::character varying NOT NULL,
    owner_name character varying(255) DEFAULT 'UNOWNED'::character varying NOT NULL,
    observed_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_artifacts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_current_coverage_state; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_current_coverage_state (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    scope_head_count bigint DEFAULT 0 NOT NULL,
    artifact_count bigint DEFAULT 0 NOT NULL,
    candidate_count bigint DEFAULT 0 NOT NULL,
    materialized_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_state FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_current_expected_candidates; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_current_expected_candidates (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    account_id character varying(64) NOT NULL,
    region character varying(64) NOT NULL,
    resource_family character varying(128) NOT NULL,
    artifact_type character varying(64) NOT NULL,
    native_kind character varying(128) NOT NULL,
    technology_id character varying(128) NOT NULL,
    environment character varying(64) NOT NULL,
    owner_name character varying(255) NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    selection character varying(32) NOT NULL,
    framework_mappings_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    assessment_id uuid,
    applicability character varying(32),
    evidence_readiness character varying(32),
    decision character varying(32),
    missing_evidence_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    input_facts_json jsonb DEFAULT '{}'::jsonb NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_expected_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_evidence_holds; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_evidence_holds (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    snapshot_body_id uuid NOT NULL,
    hold_type character varying(32) NOT NULL,
    reference_id character varying(255) NOT NULL,
    reason text NOT NULL,
    expires_at timestamp with time zone,
    released_at timestamp with time zone,
    released_by character varying(255),
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_evidence_holds_hold_type_check CHECK (((hold_type)::text = ANY ((ARRAY['ACTIVE_FINDING'::character varying, 'EXCEPTION'::character varying, 'LEGAL_HOLD'::character varying, 'REPLAY_COMMITMENT'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_evidence_holds FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_exposure_associations; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_exposure_associations (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    exposure_path_id uuid NOT NULL,
    system_id uuid,
    system_revision_id uuid,
    artifact_id uuid,
    association_role character varying(32) NOT NULL,
    CONSTRAINT ai_grid_exposure_associations_association_role_check CHECK (((association_role)::text = ANY ((ARRAY['AFFECTED_SYSTEM'::character varying, 'ENTRY_POINT'::character varying, 'IMPACT'::character varying, 'ROOT_CAUSE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_exposure_dispositions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_exposure_dispositions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    exposure_path_id uuid NOT NULL,
    disposition character varying(32) NOT NULL,
    reason text NOT NULL,
    actor character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_exposure_dispositions_disposition_check CHECK (((disposition)::text = ANY ((ARRAY['ACCEPTED'::character varying, 'REJECTED'::character varying, 'RISK_ACCEPTED'::character varying, 'NEEDS_EVIDENCE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_dispositions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_exposure_executions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_exposure_executions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    coverage_epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    evaluation_as_of timestamp with time zone NOT NULL,
    correlation_versions_json jsonb NOT NULL,
    artifact_bindings_json jsonb NOT NULL,
    relationship_ids_json jsonb NOT NULL,
    host_fact_ids_json jsonb NOT NULL,
    system_revision_ids_json jsonb NOT NULL,
    material_digest character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_executions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_exposure_observations; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_exposure_observations (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    exposure_path_id uuid NOT NULL,
    run_id uuid NOT NULL,
    state character varying(32) NOT NULL,
    entry_artifact_id uuid,
    system_id uuid,
    system_revision_id uuid,
    path_json jsonb NOT NULL,
    evidence_json jsonb NOT NULL,
    temporal_valid_from timestamp with time zone NOT NULL,
    temporal_valid_until timestamp with time zone,
    confidence double precision,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    coverage_epoch_id uuid,
    correlation_material_digest character varying(64),
    CONSTRAINT ai_grid_exposure_observations_confidence_check CHECK (((confidence IS NULL) OR ((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)))),
    CONSTRAINT ai_grid_exposure_observations_state_check CHECK (((state)::text = ANY ((ARRAY['EXPOSURE_HYPOTHESIS'::character varying, 'VALIDATED_EXPOSURE'::character varying, 'ABSENT'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_exposure_paths; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_exposure_paths (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    fingerprint character varying(64) NOT NULL,
    correlation_id character varying(128) NOT NULL,
    correlation_version character varying(32) NOT NULL,
    root_cause_artifact_id uuid NOT NULL,
    canonical_path_signature character varying(64) NOT NULL,
    state character varying(32) NOT NULL,
    status character varying(32) DEFAULT 'OPEN'::character varying NOT NULL,
    severity character varying(32) NOT NULL,
    title character varying(512) NOT NULL,
    impact text NOT NULL,
    root_cause text NOT NULL,
    breakpoint text NOT NULL,
    confidence_method character varying(128) NOT NULL,
    confidence_method_version character varying(32) NOT NULL,
    confidence double precision,
    first_observed_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    validated_at timestamp with time zone,
    closed_at timestamp with time zone,
    last_complete_run_id uuid NOT NULL,
    finding_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_complete_epoch_id uuid,
    CONSTRAINT ai_grid_exposure_paths_confidence_check CHECK (((confidence IS NULL) OR ((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)))),
    CONSTRAINT ai_grid_exposure_paths_state_check CHECK (((state)::text = ANY ((ARRAY['EXPOSURE_HYPOTHESIS'::character varying, 'VALIDATED_EXPOSURE'::character varying, 'CLOSED'::character varying])::text[]))),
    CONSTRAINT ai_grid_exposure_paths_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'CLOSED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_facts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_facts (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL,
    fact_key character varying(255) NOT NULL,
    value_type character varying(32) NOT NULL,
    value_json jsonb,
    state character varying(32) NOT NULL,
    provenance character varying(32) NOT NULL,
    evidence_class character varying(32) NOT NULL,
    source character varying(255) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    confidence_method character varying(128),
    confidence_method_version character varying(32),
    confidence double precision,
    derivation_inputs_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    fact_schema_version character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_facts_confidence_check CHECK (((confidence IS NULL) OR ((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)))),
    CONSTRAINT ai_grid_facts_state_check CHECK (((state)::text = ANY ((ARRAY['KNOWN'::character varying, 'UNKNOWN'::character varying, 'ERROR'::character varying, 'STALE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_host_context_facts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_host_context_facts (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    artifact_id uuid NOT NULL,
    fact_key character varying(255) NOT NULL,
    value_type character varying(32) NOT NULL,
    value_json jsonb,
    state character varying(32) NOT NULL,
    provenance character varying(32) NOT NULL,
    evidence_class character varying(32) NOT NULL,
    source_port character varying(32) NOT NULL,
    evidence_reference character varying(1024) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    confidence_method character varying(128) NOT NULL,
    confidence_method_version character varying(32) NOT NULL,
    confidence double precision,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    producer_id character varying(128) DEFAULT 'LEGACY_UNBOUND'::character varying NOT NULL,
    CONSTRAINT ai_grid_host_context_facts_confidence_check CHECK (((confidence IS NULL) OR ((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)))),
    CONSTRAINT ai_grid_host_context_facts_source_port_check CHECK (((source_port)::text = ANY ((ARRAY['IDENTITY'::character varying, 'DATA'::character varying, 'REACHABILITY'::character varying, 'ASSET'::character varying, 'OWNERSHIP'::character varying])::text[]))),
    CONSTRAINT ai_grid_host_context_facts_state_check CHECK (((state)::text = ANY ((ARRAY['KNOWN'::character varying, 'UNKNOWN'::character varying, 'ERROR'::character varying, 'STALE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_host_context_facts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_outbox; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_outbox (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    event_type character varying(64) NOT NULL,
    aggregate_type character varying(64) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version character varying(64) NOT NULL,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_owner_history; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_owner_history (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    artifact_id uuid NOT NULL,
    previous_owner_name character varying(255),
    previous_owner_state character varying(32),
    owner_name character varying(255),
    owner_state character varying(32) NOT NULL,
    owner_source character varying(64),
    confidence double precision,
    confidence_method character varying(128),
    confidence_method_version character varying(32),
    actor character varying(255) NOT NULL,
    reason text,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_owner_history FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_artifact_overrides; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_artifact_overrides (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    artifact_id uuid NOT NULL,
    override character varying(16) NOT NULL,
    reason text,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_artifact_overrides FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_parameters; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_parameters (
    policy_id character varying(128) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    parameters_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_by character varying(255) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_parameters FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_readiness; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_readiness (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    selection character varying(32) NOT NULL,
    readiness character varying(32) NOT NULL,
    candidate_count bigint DEFAULT 0 NOT NULL,
    applicable_count bigint DEFAULT 0 NOT NULL,
    decision_required_count bigint DEFAULT 0 NOT NULL,
    decision_ready_count bigint DEFAULT 0 NOT NULL,
    no_decision_count bigint DEFAULT 0 NOT NULL,
    error_count bigint DEFAULT 0 NOT NULL,
    missing_assessment_count bigint DEFAULT 0 NOT NULL,
    required_facts_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    available_facts_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    missing_evidence_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    coverage_epoch_id uuid,
    CONSTRAINT ai_grid_policy_readiness_readiness_check CHECK (((readiness)::text = ANY ((ARRAY['READY'::character varying, 'PARTIAL'::character varying, 'BLOCKED'::character varying, 'NOT_APPLICABLE'::character varying, 'NO_RESOURCES'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_readiness_selection_check CHECK (((selection)::text = ANY ((ARRAY['REQUIRED'::character varying, 'ENABLED'::character varying, 'PREVIEW'::character varying, 'DISABLED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_readiness FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_scopes; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_scopes (
    policy_id character varying(128) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    mode character varying(32) DEFAULT 'ALL'::character varying NOT NULL,
    condition_logic character varying(8) DEFAULT 'AND'::character varying NOT NULL,
    conditions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_by character varying(255) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_scopes FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_selection_history; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_selection_history (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    previous_selection character varying(32),
    selection character varying(32) NOT NULL,
    actor character varying(255) NOT NULL,
    reason text,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selection_history FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_policy_selections; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_policy_selections (
    policy_id character varying(128) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    selection character varying(32) NOT NULL,
    updated_by character varying(255) NOT NULL,
    reason text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_selections_selection_check CHECK (((selection)::text = ANY ((ARRAY['REQUIRED'::character varying, 'ENABLED'::character varying, 'PREVIEW'::character varying, 'DISABLED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selections FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_relationship_snapshots; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_relationship_snapshots (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    source_artifact_id uuid NOT NULL,
    target_artifact_id uuid NOT NULL,
    relationship_type character varying(128) NOT NULL,
    attributes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_retention_decisions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_retention_decisions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    snapshot_body_id uuid NOT NULL,
    decision character varying(32) NOT NULL,
    reason_code character varying(64) NOT NULL,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_retention_decisions_decision_check CHECK (((decision)::text = ANY ((ARRAY['RETAIN'::character varying, 'ARCHIVE'::character varying, 'PURGE_BLOCKED'::character varying, 'PURGE_ELIGIBLE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_decisions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_retention_policies; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_retention_policies (
    retention_class character varying(32) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    retain_days integer NOT NULL,
    archive_after_days integer,
    restricted boolean DEFAULT false NOT NULL,
    updated_by character varying(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_retention_policies_check CHECK (((archive_after_days IS NULL) OR ((archive_after_days >= 0) AND (archive_after_days < retain_days)))),
    CONSTRAINT ai_grid_retention_policies_retain_days_check CHECK ((retain_days > 0)),
    CONSTRAINT ai_grid_retention_policies_retention_class_check CHECK (((retention_class)::text = ANY ((ARRAY['HOT'::character varying, 'ARCHIVE'::character varying, 'RESTRICTED_EVIDENCE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_policies FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_retention_purge_audit; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_retention_purge_audit (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    snapshot_body_id uuid NOT NULL,
    content_hash character varying(64) NOT NULL,
    byte_size bigint NOT NULL,
    reason_code character varying(64) NOT NULL,
    purged_by character varying(255) NOT NULL,
    purged_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_retention_purge_audit_byte_size_check CHECK ((byte_size >= 0))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_purge_audit FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_run_metrics; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_run_metrics (
    run_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    completed_scope_count bigint DEFAULT 0 NOT NULL,
    processing_duration_ms bigint DEFAULT 0 NOT NULL,
    provider_api_calls bigint,
    provider_call_measurement_state character varying(32) DEFAULT 'UNAVAILABLE'::character varying NOT NULL,
    artifact_count bigint DEFAULT 0 NOT NULL,
    snapshot_manifest_count bigint DEFAULT 0 NOT NULL,
    snapshot_bytes bigint DEFAULT 0 NOT NULL,
    new_snapshot_bytes bigint DEFAULT 0 NOT NULL,
    fact_count bigint DEFAULT 0 NOT NULL,
    assessment_count bigint DEFAULT 0 NOT NULL,
    pass_count bigint DEFAULT 0 NOT NULL,
    fail_count bigint DEFAULT 0 NOT NULL,
    no_decision_count bigint DEFAULT 0 NOT NULL,
    open_gap_count bigint DEFAULT 0 NOT NULL,
    first_inventory_at timestamp with time zone,
    first_decision_at timestamp with time zone,
    first_finding_at timestamp with time zone,
    first_gap_at timestamp with time zone,
    first_recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    provider character varying(32),
    retained_snapshot_bytes bigint DEFAULT 0 NOT NULL,
    budget_state character varying(32) DEFAULT 'WITHIN_BUDGET'::character varying NOT NULL,
    connector_config_id uuid,
    expected_assessment_count bigint DEFAULT 0 NOT NULL,
    missing_assessment_count bigint DEFAULT 0 NOT NULL,
    decision_reachable_count bigint DEFAULT 0 NOT NULL,
    owner_facing_expected_count bigint DEFAULT 0 NOT NULL,
    owner_facing_decision_count bigint DEFAULT 0 NOT NULL,
    decision_reachability_percent double precision DEFAULT 0 NOT NULL,
    owner_facing_utility_percent double precision DEFAULT 0 NOT NULL,
    baseline_run boolean DEFAULT false NOT NULL,
    first_run_target_percent double precision DEFAULT 80 NOT NULL,
    first_run_target_met boolean,
    first_owner_routed_finding_at timestamp with time zone,
    first_exposure_hypothesis_at timestamp with time zone,
    graph_recomputed_node_count bigint DEFAULT 0 NOT NULL,
    graph_recomputed_edge_count bigint DEFAULT 0 NOT NULL,
    graph_traversed_path_count bigint DEFAULT 0 NOT NULL,
    exposure_path_count bigint DEFAULT 0 NOT NULL,
    graph_recompute_duration_ms bigint DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_metrics FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_run_scope_metrics; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_run_scope_metrics (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    scope_key character varying(512) NOT NULL,
    processing_duration_ms bigint NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_run_scope_metrics_processing_duration_ms_check CHECK ((processing_duration_ms >= 0))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_scope_metrics FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_scan_cadence_rules; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_scan_cadence_rules (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    provider character varying(32) NOT NULL,
    resource_family character varying(128) DEFAULT '*'::character varying NOT NULL,
    environment character varying(64) DEFAULT '*'::character varying NOT NULL,
    criticality character varying(32) DEFAULT '*'::character varying NOT NULL,
    minimum_interval_seconds bigint NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_by character varying(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_scan_cadence_rules_minimum_interval_seconds_check CHECK ((minimum_interval_seconds >= 0))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_scan_cadence_rules FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_setup_actions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_setup_actions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid,
    policy_id character varying(128),
    fingerprint character varying(64) NOT NULL,
    priority integer NOT NULL,
    category character varying(32) NOT NULL,
    action_code character varying(64) NOT NULL,
    title character varying(255) NOT NULL,
    detail text NOT NULL,
    evidence_key character varying(512),
    status character varying(32) DEFAULT 'OPEN'::character varying NOT NULL,
    first_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    coverage_epoch_id uuid,
    CONSTRAINT ai_grid_setup_actions_priority_check CHECK (((priority >= 1) AND (priority <= 100))),
    CONSTRAINT ai_grid_setup_actions_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'RESOLVED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_setup_actions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_snapshot_bodies; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_snapshot_bodies (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    content_hash character varying(64) NOT NULL,
    content_json jsonb NOT NULL,
    byte_size bigint NOT NULL,
    redaction_profile character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    first_run_id uuid,
    retention_class character varying(32) DEFAULT 'HOT'::character varying NOT NULL,
    retain_until timestamp with time zone DEFAULT (now() + '90 days'::interval) NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    replay_commitment_until timestamp with time zone,
    retention_state character varying(32) DEFAULT 'RETAINED'::character varying NOT NULL,
    CONSTRAINT ai_grid_snapshot_bodies_byte_size_check CHECK ((byte_size >= 0))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_bodies FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_snapshot_manifests; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_snapshot_manifests (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    scope_key character varying(512) NOT NULL,
    body_id uuid NOT NULL,
    schema_version character varying(32) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    connector_config_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_lineage_events; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_lineage_events (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    event_type character varying(32) NOT NULL,
    run_id uuid,
    rationale text NOT NULL,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    actor character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_system_lineage_events_event_type_check CHECK (((event_type)::text = ANY ((ARRAY['SPLIT'::character varying, 'MERGED'::character varying, 'RETIRED'::character varying, 'SUCCESSOR'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_events FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_lineage_participants; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_lineage_participants (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    event_id uuid NOT NULL,
    system_id uuid NOT NULL,
    system_revision_id uuid,
    participant_role character varying(16) NOT NULL,
    CONSTRAINT ai_grid_system_lineage_participants_participant_role_check CHECK (((participant_role)::text = ANY ((ARRAY['PREDECESSOR'::character varying, 'SUCCESSOR'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_membership_decisions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_membership_decisions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    system_id uuid NOT NULL,
    resulting_revision_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    decision character varying(16) NOT NULL,
    reason text NOT NULL,
    actor character varying(255) NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_system_membership_decisions_decision_check CHECK (((decision)::text = ANY ((ARRAY['ACCEPT'::character varying, 'REJECT'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_membership_overrides; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_membership_overrides (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    system_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    decision character varying(16) NOT NULL,
    reason text NOT NULL,
    actor character varying(255) NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_system_membership_overrides_decision_check CHECK (((decision)::text = ANY ((ARRAY['ACCEPT'::character varying, 'REJECT'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_overrides FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_memberships; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_memberships (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    system_revision_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    membership_state character varying(32) NOT NULL,
    confidence_method character varying(128) NOT NULL,
    confidence_method_version character varying(32) NOT NULL,
    confidence double precision NOT NULL,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    decided_by character varying(255),
    decided_at timestamp with time zone,
    CONSTRAINT ai_grid_system_memberships_confidence_check CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)))
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_system_revisions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_system_revisions (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    system_id uuid NOT NULL,
    revision integer NOT NULL,
    membership_hash character varying(64) NOT NULL,
    source character varying(32) NOT NULL,
    rationale text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    run_id uuid,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    coverage_epoch_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_revisions FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_systems; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_grid_systems (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    stable_key character varying(64) NOT NULL,
    name character varying(512) NOT NULL,
    status character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    current_revision integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    root_artifact_id uuid,
    retired_at timestamp with time zone
);

ALTER TABLE ONLY ${tenantSchema}.ai_grid_systems FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_artifact_sources; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_artifact_sources (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    artifact_id uuid NOT NULL,
    connector_config_id uuid,
    scope_key character varying(512) NOT NULL,
    run_id uuid NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    evidence_hash character varying(128) NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_artifacts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_artifacts (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    provider character varying(32) NOT NULL,
    provider_resource_id character varying(1024) NOT NULL,
    artifact_type character varying(64) NOT NULL,
    native_kind character varying(128) NOT NULL,
    name character varying(512) NOT NULL,
    account_id character varying(64) NOT NULL,
    region character varying(64) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    attributes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    first_observed_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    deactivated_at timestamp with time zone,
    owner_name character varying(255),
    owner_state character varying(32) DEFAULT 'UNOWNED'::character varying NOT NULL,
    owner_source character varying(64),
    owner_confidence double precision,
    owner_confidence_method character varying(128),
    owner_confidence_method_version character varying(32),
    owner_updated_at timestamp with time zone,
    business_criticality character varying(32),
    environment character varying(64),
    pii_scan_status character varying(32) DEFAULT 'NOT_APPLICABLE'::character varying NOT NULL,
    pii_source character varying(32),
    pii_info_types jsonb DEFAULT '[]'::jsonb NOT NULL,
    pii_finding_count integer DEFAULT 0 NOT NULL,
    pii_last_scanned_at timestamp with time zone,
    CONSTRAINT ai_security_artifacts_owner_confidence_check CHECK (((owner_confidence IS NULL) OR ((owner_confidence >= (0)::double precision) AND (owner_confidence <= (1)::double precision)))),
    CONSTRAINT ai_security_artifacts_owner_state_check CHECK (((owner_state)::text = ANY ((ARRAY['CONFIRMED'::character varying, 'INFERRED'::character varying, 'CANDIDATE'::character varying, 'UNOWNED'::character varying])::text[]))),
    CONSTRAINT ai_security_artifacts_pii_finding_count_check CHECK ((pii_finding_count >= 0)),
    CONSTRAINT ai_security_artifacts_pii_scan_status_check CHECK (((pii_scan_status)::text = ANY ((ARRAY['UNKNOWN'::character varying, 'NOT_APPLICABLE'::character varying, 'NOT_SCANNED'::character varying, 'SCANNED_CLEAN'::character varying, 'SCANNED_PII_FOUND'::character varying, 'LOOKUP_FAILED'::character varying])::text[]))),
    CONSTRAINT ai_security_artifacts_pii_source_check CHECK (((pii_source IS NULL) OR ((pii_source)::text = ANY ((ARRAY['AWS_MACIE'::character varying, 'AZURE_PURVIEW'::character varying])::text[]))))
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifacts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_azure_credential_profiles; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_azure_credential_profiles (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    name character varying(255) NOT NULL,
    auth_type character varying(32) NOT NULL,
    azure_tenant_id character varying(128) NOT NULL,
    client_id character varying(255),
    active_secret_ciphertext text,
    pending_secret_ciphertext text,
    active_secret_expires_at timestamp with time zone,
    pending_secret_expires_at timestamp with time zone,
    status character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    last_verified_at timestamp with time zone,
    last_verification_status character varying(32),
    expiry_warning_days integer,
    created_by character varying(255) NOT NULL,
    updated_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by character varying(255),
    CONSTRAINT ai_security_azure_credential_auth_check CHECK (((auth_type)::text = ANY ((ARRAY['CLIENT_SECRET'::character varying, 'WORKLOAD_FEDERATION'::character varying, 'MANAGED_IDENTITY'::character varying])::text[]))),
    CONSTRAINT ai_security_azure_credential_status_check CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'EXPIRED'::character varying, 'REVOKED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_azure_credential_profiles FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_connector_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_connector_configs (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    provider character varying(32) NOT NULL,
    account_id character varying(64) NOT NULL,
    role_arn character varying(512),
    external_id_ciphertext text,
    regions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    credential_profile_id uuid,
    source_config_id uuid,
    source_target_id uuid,
    provider_tenant_id character varying(128),
    resource_families_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    foundry_endpoint_url character varying(500),
    purview_account_name character varying(255)
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_connector_configs FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_observation_receipts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_observation_receipts (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    scope_key character varying(512) NOT NULL,
    chunk_sequence integer NOT NULL,
    idempotency_key character varying(256) NOT NULL,
    content_hash character varying(128) NOT NULL,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_observation_receipts FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_relationships; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_relationships (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    source_artifact_id uuid NOT NULL,
    target_artifact_id uuid NOT NULL,
    relationship_type character varying(128) NOT NULL,
    attributes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    scope_key character varying(512) NOT NULL,
    run_id uuid NOT NULL,
    active boolean DEFAULT true NOT NULL,
    first_observed_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships FORCE ROW LEVEL SECURITY;


--
-- Name: ai_security_snapshot_scopes; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ai_security_snapshot_scopes (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    run_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    account_id character varying(64) NOT NULL,
    region character varying(64) NOT NULL,
    resource_family character varying(128) NOT NULL,
    scope_key character varying(512) NOT NULL,
    status character varying(32) NOT NULL,
    expected_chunks integer DEFAULT 1 NOT NULL,
    accepted_chunks integer DEFAULT 0 NOT NULL,
    diagnostic_code character varying(64),
    diagnostic_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone
);

ALTER TABLE ONLY ${tenantSchema}.ai_security_snapshot_scopes FORCE ROW LEVEL SECURITY;


--
-- Name: applicability_assessments; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.applicability_assessments (
    id bigint NOT NULL,
    affected_components text,
    assessed_by character varying(100),
    attack_vector_accessible boolean,
    completed_at timestamp with time zone,
    confidence_level character varying(20),
    configuration_details text,
    created_at timestamp with time zone NOT NULL,
    current_version character varying(100),
    detection_method character varying(100),
    final_result character varying(50),
    fixed_version character varying(100),
    justification text,
    recommended_action text,
    software_detected boolean,
    status character varying(50) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    vulnerable_configuration boolean,
    vulnerable_version_present boolean,
    vulnerable_version_range character varying(200),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    vulnerability_id uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.applicability_assessments FORCE ROW LEVEL SECURITY;


--
-- Name: applicability_assessments_id_seq; Type: SEQUENCE; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.applicability_assessments ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME ${tenantSchema}.applicability_assessments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: assets; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.assets (
    id uuid NOT NULL,
    assigned_to character varying(255),
    base_image_digest character varying(255),
    business_criticality character varying(255) NOT NULL,
    cloud_account_id character varying(255),
    cloud_arn character varying(255),
    cloud_availability_zone character varying(255),
    cloud_instance_type character varying(255),
    cloud_launch_time timestamp with time zone,
    cloud_provider character varying(255),
    cloud_region character varying(255),
    cloud_resource_type character varying(255),
    cloud_subnet_id character varying(255),
    cloud_tags_json character varying(255),
    cloud_vpc_id character varying(255),
    created_at timestamp with time zone NOT NULL,
    department character varying(255),
    environment character varying(255),
    identifier character varying(255) NOT NULL,
    image_digest character varying(255),
    image_repository character varying(255),
    image_tag character varying(255),
    last_cmdb_sync_at timestamp with time zone,
    last_inventory_at timestamp with time zone,
    managed_by character varying(255),
    missing_iam_instance_profile boolean,
    name character varying(255) NOT NULL,
    owner_email character varying(255),
    owner_team character varying(255),
    service_name character varying(255),
    ssm_inventory_available boolean,
    ssm_inventory_last_captured_at timestamp with time zone,
    ssm_last_ping_at timestamp with time zone,
    ssm_managed boolean,
    ssm_ping_status character varying(255),
    state character varying(255) NOT NULL,
    support_group character varying(255),
    type character varying(255) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT assets_business_criticality_check CHECK (((business_criticality)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[]))),
    CONSTRAINT assets_state_check CHECK (((state)::text = ANY ((ARRAY['ACTIVE'::character varying, 'INACTIVE'::character varying, 'RETIRED'::character varying, 'DECOMMISSIONED'::character varying])::text[]))),
    CONSTRAINT assets_type_check CHECK (((type)::text = ANY ((ARRAY['APPLICATION'::character varying, 'HOST'::character varying, 'CONTAINER_IMAGE'::character varying, 'CLOUD_RESOURCE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.assets FORCE ROW LEVEL SECURITY;


--
-- Name: audit_events; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.audit_events (
    id uuid NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    actor_subject character varying(255) NOT NULL,
    actor_role character varying(64),
    action character varying(160) NOT NULL,
    target_type character varying(120),
    target_id character varying(255),
    request_id character varying(120),
    source_ip character varying(80),
    outcome character varying(32) NOT NULL,
    details_json jsonb,
    actor_user_id uuid,
    tenant_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.audit_events FORCE ROW LEVEL SECURITY;


--
-- Name: aws_discovery_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.aws_discovery_configs (
    id uuid NOT NULL,
    access_key_id character varying(255),
    auth_type character varying(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    aws_account_id character varying(255),
    created_at timestamp with time zone NOT NULL,
    credential_secret character varying(255),
    cross_account_role_arn character varying(255),
    enabled boolean NOT NULL,
    external_id character varying(255),
    interval_minutes integer NOT NULL,
    last_sync_at timestamp with time zone,
    last_test_message character varying(255),
    last_test_status character varying(255),
    last_tested_at timestamp with time zone,
    regions_json character varying(255) NOT NULL,
    resource_types_json character varying(255) NOT NULL,
    source_system character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT aws_discovery_configs_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['INSTANCE_METADATA'::character varying, 'ACCESS_KEY'::character varying, 'CROSS_ACCOUNT_ROLE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_configs FORCE ROW LEVEL SECURITY;


--
-- Name: aws_discovery_targets; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.aws_discovery_targets (
    id uuid NOT NULL,
    account_id character varying(255),
    account_name character varying(255),
    created_at timestamp with time zone NOT NULL,
    enabled boolean NOT NULL,
    external_id character varying(255),
    last_sync_at timestamp with time zone,
    last_test_message character varying(255),
    last_test_status character varying(255),
    last_tested_at timestamp with time zone,
    regions_json character varying(255) NOT NULL,
    resource_types_json character varying(255) NOT NULL,
    role_arn character varying(255),
    updated_at timestamp with time zone NOT NULL,
    config_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_targets FORCE ROW LEVEL SECURITY;


--
-- Name: azure_discovery_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.azure_discovery_configs (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    source_system character varying(80) DEFAULT 'azure'::character varying NOT NULL,
    auth_type character varying(32) DEFAULT 'CLIENT_SECRET'::character varying NOT NULL,
    azure_tenant_id character varying(128),
    client_id character varying(255),
    client_secret text,
    subscription_ids_json text DEFAULT '[]'::text NOT NULL,
    regions_json text DEFAULT '["eastus2"]'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    auto_sync_enabled boolean DEFAULT false NOT NULL,
    interval_minutes integer DEFAULT 1440 NOT NULL,
    last_test_status character varying(64),
    last_test_message character varying(2000),
    last_tested_at timestamp with time zone,
    last_sync_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT azure_discovery_configs_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['CLIENT_SECRET'::character varying, 'MANAGED_IDENTITY'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_configs FORCE ROW LEVEL SECURITY;


--
-- Name: azure_discovery_targets; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.azure_discovery_targets (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    config_id uuid NOT NULL,
    subscription_id character varying(64),
    subscription_name character varying(255),
    enabled boolean DEFAULT true NOT NULL,
    regions_json text DEFAULT '["eastus2"]'::text NOT NULL,
    last_test_status character varying(64),
    last_test_message character varying(2000),
    last_tested_at timestamp with time zone,
    last_sync_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_targets FORCE ROW LEVEL SECURITY;


--
-- Name: bom_component_evidence; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.bom_component_evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    bom_component_id uuid NOT NULL,
    bom_id uuid NOT NULL,
    evidence_type character varying(40) NOT NULL,
    evidence_key text,
    evidence_value text,
    source_system character varying(80),
    source_reference text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.bom_component_evidence FORCE ROW LEVEL SECURITY;


--
-- Name: bom_component_vulnerability_links; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.bom_component_vulnerability_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    bom_component_id uuid NOT NULL,
    bom_id uuid NOT NULL,
    vulnerability_key character varying(128) NOT NULL,
    vulnerability_source character varying(40) DEFAULT 'NVD'::character varying NOT NULL,
    relation_type character varying(40) DEFAULT 'CVE'::character varying NOT NULL,
    match_source character varying(80),
    match_confidence numeric(5,2),
    direct_match boolean DEFAULT false NOT NULL,
    correlation_evidence_json jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.bom_component_vulnerability_links FORCE ROW LEVEL SECURITY;


--
-- Name: bom_component_workflows; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.bom_component_workflows (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    bom_component_id uuid NOT NULL,
    vulnerability_link_id uuid,
    workflow_type character varying(40) DEFAULT 'INVESTIGATION'::character varying NOT NULL,
    workflow_status character varying(40) DEFAULT 'DISCOVERED'::character varying NOT NULL,
    workflow_reason text,
    investigation_key character varying(128),
    finding_id uuid,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone
);

ALTER TABLE ONLY ${tenantSchema}.bom_component_workflows FORCE ROW LEVEL SECURITY;


--
-- Name: bom_components; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.bom_components (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    bom_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    name text NOT NULL,
    version text,
    purl text,
    cpe text,
    license text,
    supplier text,
    component_type character varying(40),
    category character varying(30) DEFAULT 'UNMATCHED'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    hashes jsonb,
    properties jsonb,
    bom_ref text,
    group_name text,
    scope text,
    swid text,
    external_references jsonb,
    workflow_status character varying(40) DEFAULT 'DISCOVERED'::character varying NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.bom_components FORCE ROW LEVEL SECURITY;


--
-- Name: bom_ingestion_records; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.bom_ingestion_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    sbom_upload_id uuid,
    asset_id uuid,
    bom_type character varying(20) NOT NULL,
    format character varying(20),
    format_version character varying(10),
    serial_number text,
    supplier character varying(255),
    source_method character varying(20) DEFAULT 'URL'::character varying NOT NULL,
    source_url text,
    component_count integer DEFAULT 0 NOT NULL,
    status character varying(20) DEFAULT 'ACTIVE'::character varying NOT NULL,
    superseded_by uuid,
    ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    ingested_by text,
    source_type character varying(40) DEFAULT 'URL'::character varying NOT NULL,
    source_system character varying(80),
    source_reference text,
    source_endpoint text,
    source_label text,
    spec_family character varying(30) DEFAULT 'UNKNOWN'::character varying NOT NULL,
    document_format character varying(20) DEFAULT 'UNKNOWN'::character varying NOT NULL,
    document_name text,
    content_type character varying(120),
    content_length_bytes bigint,
    checksum_sha256 character varying(128),
    previous_bom_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.bom_ingestion_records FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_activities; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_activities (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    activity_type character varying(64) NOT NULL,
    actor character varying(255) NOT NULL,
    body text NOT NULL,
    metadata_json jsonb,
    created_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_activities FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_delivery_attempts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_delivery_attempts (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    target_type character varying(32) NOT NULL,
    target_label character varying(255) NOT NULL,
    target_address character varying(255),
    subject character varying(500) NOT NULL,
    delivery_state character varying(32) NOT NULL,
    provider_message_id character varying(255),
    detail character varying(1000),
    created_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_delivery_attempts FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_exceptions; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_exceptions (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    finding_display_id character varying(64),
    asset_name character varying(255),
    package_name character varying(255),
    title character varying(255) NOT NULL,
    reason text NOT NULL,
    status character varying(32) NOT NULL,
    requested_by character varying(255) NOT NULL,
    requested_at timestamp with time zone NOT NULL,
    decision_due_at timestamp with time zone,
    decisioned_by character varying(255),
    decisioned_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_exceptions FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_notes; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_notes (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    author character varying(255) NOT NULL,
    body text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_notes FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_notify_groups; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_notify_groups (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    group_name character varying(255) NOT NULL,
    role_label character varying(128),
    trigger_summary character varying(255),
    notifications_paused boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone NOT NULL,
    group_email character varying(255),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_notify_groups FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_vulnerabilities; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_vulnerabilities (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    external_id character varying(64) NOT NULL,
    title character varying(500),
    severity character varying(32),
    created_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_watchlist_entries; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaign_watchlist_entries (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    entry_type character varying(32) NOT NULL,
    label character varying(255) NOT NULL,
    email character varying(255),
    trigger_policy character varying(64),
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaign_watchlist_entries FORCE ROW LEVEL SECURITY;


--
-- Name: campaigns; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.campaigns (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    name character varying(255) NOT NULL,
    summary text,
    status character varying(32) NOT NULL,
    created_by character varying(255) NOT NULL,
    due_at timestamp with time zone,
    started_at timestamp with time zone,
    paused_at timestamp with time zone,
    closed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.campaigns FORCE ROW LEVEL SECURITY;


--
-- Name: cbom_components; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.cbom_components (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    asset_id uuid,
    source_bom_id uuid NOT NULL,
    bom_ref text,
    component_fingerprint text NOT NULL,
    name text NOT NULL,
    description text,
    asset_type character varying(60) NOT NULL,
    component_type text,
    primitive text,
    parameter_set_identifier text,
    key_size integer,
    curve text,
    padding text,
    protocol_version text,
    state text,
    format text,
    storage_location text,
    transmission text,
    sensitivity text,
    used_in text,
    not_before date,
    not_after date,
    issuer text,
    subject text,
    serial_number text,
    signature_algorithm text,
    key_usage text,
    risk_score numeric(4,2),
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.cbom_components FORCE ROW LEVEL SECURITY;


--
-- Name: cbom_posture_summary; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.cbom_posture_summary (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    asset_id uuid NOT NULL,
    last_source_bom_id uuid,
    total_components integer DEFAULT 0 NOT NULL,
    critical_findings integer DEFAULT 0 NOT NULL,
    high_findings integer DEFAULT 0 NOT NULL,
    medium_findings integer DEFAULT 0 NOT NULL,
    low_findings integer DEFAULT 0 NOT NULL,
    info_findings integer DEFAULT 0 NOT NULL,
    accepted_findings integer DEFAULT 0 NOT NULL,
    quantum_vulnerable integer DEFAULT 0 NOT NULL,
    weak_algorithms integer DEFAULT 0 NOT NULL,
    expiring_certs integer DEFAULT 0 NOT NULL,
    posture_score numeric(4,2),
    last_evaluated_at timestamp with time zone
);

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary FORCE ROW LEVEL SECURITY;


--
-- Name: cbom_risk_findings; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.cbom_risk_findings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    cbom_component_id uuid NOT NULL,
    rule_id character varying(100) NOT NULL,
    rule_version character varying(20) DEFAULT '1'::character varying NOT NULL,
    finding_fingerprint text NOT NULL,
    risk_class character varying(80) NOT NULL,
    severity character varying(20) NOT NULL,
    title text NOT NULL,
    detail text,
    evidence jsonb,
    recommendation text,
    status character varying(20) DEFAULT 'OPEN'::character varying NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.cbom_risk_findings FORCE ROW LEVEL SECURITY;


--
-- Name: ci_aliases; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ci_aliases (
    id uuid NOT NULL,
    alias_name character varying(255) NOT NULL,
    confidence double precision,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    normalized_alias_name character varying(255) NOT NULL,
    source_system character varying(64) NOT NULL,
    ci_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ci_aliases FORCE ROW LEVEL SECURITY;


--
-- Name: cis; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.cis (
    id uuid NOT NULL,
    assigned_to character varying(255),
    business_criticality character varying(32) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    department character varying(255),
    display_name character varying(255) NOT NULL,
    environment character varying(64),
    last_cmdb_sync_at timestamp with time zone,
    last_inventory_at timestamp with time zone,
    managed_by character varying(255),
    owner_email character varying(255),
    support_group character varying(255),
    sys_id character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    asset_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.cis FORCE ROW LEVEL SECURITY;


--
-- Name: component_vulnerability_states; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.component_vulnerability_states (
    id uuid NOT NULL,
    analyst_disposition character varying(40),
    analyst_reason text,
    analyst_updated_at timestamp with time zone,
    analyst_updated_by character varying(255),
    applicability_reason character varying(255),
    applicability_reason_detail text,
    applicability_state character varying(40) NOT NULL,
    confidence_score double precision,
    created_at timestamp with time zone NOT NULL,
    eligible_for_finding boolean NOT NULL,
    impact_reason character varying(255),
    impact_reason_detail text,
    impact_state character varying(40) NOT NULL,
    last_evaluated_at timestamp with time zone NOT NULL,
    matched_by character varying(120),
    matched_vex_assertion_id uuid,
    precedence_reason character varying(120),
    selected_target_source character varying(255),
    state_changed_at timestamp with time zone NOT NULL,
    trace_json text,
    updated_at timestamp with time zone NOT NULL,
    vex_freshness character varying(40),
    vex_provider character varying(120),
    vex_source character varying(120),
    vex_status character varying(80),
    vex_target_id uuid,
    component_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    vulnerability_id uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states FORCE ROW LEVEL SECURITY;


--
-- Name: dashboard_noise_reduction_projection; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.dashboard_noise_reduction_projection (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    never_opened_not_applicable bigint DEFAULT 0 NOT NULL,
    deferred_under_investigation bigint DEFAULT 0 NOT NULL,
    category_counts_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_computed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.dashboard_noise_reduction_projection FORCE ROW LEVEL SECURITY;


--
-- Name: demo_invites; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.demo_invites (
    id uuid NOT NULL,
    token character varying(96) NOT NULL,
    email character varying(255) NOT NULL,
    status character varying(32) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    last_sent_at timestamp with time zone,
    request_id uuid,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.demo_invites FORCE ROW LEVEL SECURITY;


--
-- Name: demo_requests; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.demo_requests (
    id uuid NOT NULL,
    company character varying(255) NOT NULL,
    company_size character varying(80),
    decided_at timestamp with time zone,
    decided_by character varying(255),
    email character varying(255) NOT NULL,
    full_name character varying(255) NOT NULL,
    notes character varying(2000),
    rejection_reason character varying(255),
    requested_at timestamp with time zone NOT NULL,
    role_title character varying(255),
    status character varying(32) NOT NULL,
    tenant_id uuid,
    use_case character varying(120),
    bootstrap_status character varying(64)
);


--
-- Name: discovery_models; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.discovery_models (
    id uuid NOT NULL,
    approved boolean,
    created_at timestamp with time zone NOT NULL,
    display_name character varying(500),
    full_version character varying(255),
    language character varying(120),
    low_confidence boolean,
    ml_model_version character varying(120),
    normalization_status character varying(80),
    normalized_product character varying(255),
    normalized_publisher character varying(255),
    normalized_version character varying(255),
    platform character varying(120),
    primary_key character varying(500) NOT NULL,
    product_hash character varying(255),
    updated_at timestamp with time zone NOT NULL,
    version_hash character varying(255),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.discovery_models FORCE ROW LEVEL SECURITY;


--
-- Name: finding_comments; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_comments (
    id uuid NOT NULL,
    author character varying(255) NOT NULL,
    body character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    finding_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_comments FORCE ROW LEVEL SECURITY;


--
-- Name: finding_delta_queue; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_delta_queue (
    id bigint NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    completed_at timestamp with time zone,
    component_id uuid,
    dedupe_key character varying(700) NOT NULL,
    enqueued_at timestamp with time zone DEFAULT now() NOT NULL,
    error_message text,
    event_type character varying(30) NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    processing_started_at timestamp with time zone,
    source_key character varying(500),
    source_tag character varying(255),
    status character varying(20) DEFAULT 'PENDING'::character varying NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    visible_after timestamp with time zone DEFAULT now() NOT NULL,
    vulnerability_id uuid
);

ALTER TABLE ONLY ${tenantSchema}.finding_delta_queue FORCE ROW LEVEL SECURITY;


--
-- Name: finding_delta_queue_id_seq; Type: SEQUENCE; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_delta_queue ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME ${tenantSchema}.finding_delta_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: finding_events; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_events (
    id uuid NOT NULL,
    actor character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    details_json jsonb,
    event_type character varying(255) NOT NULL,
    summary character varying(255) NOT NULL,
    finding_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_events FORCE ROW LEVEL SECURITY;


--
-- Name: finding_list_projection; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_list_projection (
    finding_id uuid NOT NULL,
    display_id character varying(32),
    severity character varying(32),
    status character varying(32) NOT NULL,
    decision_state character varying(64),
    creation_source character varying(32),
    match_method character varying(64),
    vex_status character varying(64),
    vex_freshness character varying(64),
    vex_provider character varying(128),
    confidence_score double precision,
    vulnerability_id character varying(64),
    package_name character varying(255),
    ecosystem character varying(64),
    owner_group character varying(255),
    assigned_to character varying(255),
    incident_id character varying(64),
    due_at timestamp with time zone,
    asset_name character varying(255),
    support_group character varying(255),
    patch_available boolean NOT NULL,
    suppressed_until timestamp with time zone,
    risk_score double precision NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    first_observed_at timestamp with time zone,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_list_projection FORCE ROW LEVEL SECURITY;


--
-- Name: finding_reviews; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_reviews (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    finding_id uuid NOT NULL,
    disposition character varying(32) NOT NULL,
    reason text,
    policy_version character varying(32),
    reviewed_by character varying(255) NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_reviews FORCE ROW LEVEL SECURITY;


--
-- Name: finding_subjects; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_subjects (
    id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    finding_id uuid NOT NULL,
    subject_type character varying(32) NOT NULL,
    subject_id uuid NOT NULL,
    subject_revision character varying(64),
    subject_role character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_subjects FORCE ROW LEVEL SECURITY;


--
-- Name: finding_workspace_projection_status; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.finding_workspace_projection_status (
    projection_key character varying(64) NOT NULL,
    last_computed_at timestamp with time zone NOT NULL,
    finding_count bigint NOT NULL,
    source_finding_count bigint DEFAULT 0 NOT NULL,
    last_rebuild_duration_ms bigint,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.finding_workspace_projection_status FORCE ROW LEVEL SECURITY;


--
-- Name: findings; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.findings (
    id uuid NOT NULL,
    assigned_at timestamp with time zone,
    assigned_by character varying(255),
    assigned_to character varying(255),
    confidence_score double precision,
    auto_close_eligible_at timestamp with time zone,
    closed_at timestamp with time zone,
    closed_by character varying(255),
    closed_reason character varying(80),
    closed_rule_id uuid,
    consecutive_misses integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone NOT NULL,
    creation_source character varying(255) NOT NULL,
    decision_state character varying(255),
    display_id character varying(16) NOT NULL,
    due_at timestamp with time zone,
    evidence jsonb,
    first_observed_at timestamp with time zone,
    incident_id character varying(64),
    incident_status character varying(64),
    last_observed_at timestamp with time zone,
    last_observed_run_id uuid,
    matched_by character varying(255) NOT NULL,
    matched_vex_assertion_id uuid,
    owner_group character varying(255),
    precedence_trace text,
    risk_score double precision NOT NULL,
    severity_override character varying(16),
    status character varying(255) NOT NULL,
    suppressed_by_rule_id uuid,
    suppressed_by_rule_name character varying(255),
    suppressed_until timestamp with time zone,
    suppression_reason character varying(2000),
    updated_at timestamp with time zone NOT NULL,
    vex_freshness character varying(64),
    vex_provider character varying(128),
    vex_status character varying(64),
    asset_id uuid,
    component_id uuid,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    vulnerability_id uuid,
    finding_kind character varying(32) DEFAULT 'VULNERABILITY'::character varying NOT NULL,
    fingerprint character varying(64),
    workflow_class character varying(32),
    title character varying(512),
    policy_id character varying(128),
    policy_version character varying(32),
    reason_code character varying(128),
    assessment_id uuid,
    CONSTRAINT findings_creation_source_check CHECK (((creation_source)::text = ANY ((ARRAY['MANUAL'::character varying, 'AUTOMATIC'::character varying, 'AI_SECURITY'::character varying])::text[]))),
    CONSTRAINT findings_decision_state_check CHECK (((decision_state)::text = ANY ((ARRAY['AFFECTED'::character varying, 'NOT_AFFECTED'::character varying, 'FIXED'::character varying, 'UNDER_INVESTIGATION'::character varying, 'NEEDS_REVIEW'::character varying])::text[]))),
    CONSTRAINT findings_kind_check CHECK (((finding_kind)::text = ANY ((ARRAY['VULNERABILITY'::character varying, 'AI_POSTURE'::character varying, 'AI_EXPOSURE'::character varying])::text[]))),
    CONSTRAINT findings_status_check CHECK (((status)::text = ANY ((ARRAY['OPEN'::character varying, 'RESOLVED'::character varying, 'SUPPRESSED'::character varying, 'AUTO_CLOSED'::character varying])::text[]))),
    CONSTRAINT findings_vulnerability_subject_check CHECK ((((finding_kind)::text <> 'VULNERABILITY'::text) OR ((vulnerability_id IS NOT NULL) AND ((asset_id IS NOT NULL) OR (component_id IS NOT NULL)))))
);

ALTER TABLE ONLY ${tenantSchema}.findings FORCE ROW LEVEL SECURITY;


--
-- Name: fix_records; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.fix_records (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    cve_id character varying(255) NOT NULL,
    description text,
    fix_type character varying(255) NOT NULL,
    generated_at timestamp with time zone NOT NULL,
    os_hint character varying(255),
    recommendation_source character varying(255) NOT NULL,
    related_cve_ids jsonb,
    software_entities jsonb,
    source_urls jsonb,
    summary character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.fix_records FORCE ROW LEVEL SECURITY;


--
-- Name: github_sbom_sources; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.github_sbom_sources (
    id uuid NOT NULL,
    asset_identifier character varying(255) NOT NULL,
    asset_name character varying(255) NOT NULL,
    asset_type character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    enabled boolean NOT NULL,
    frequency character varying(255) NOT NULL,
    interval_minutes integer NOT NULL,
    last_error character varying(2000),
    last_run_at timestamp with time zone,
    last_run_status character varying(64),
    name character varying(255) NOT NULL,
    owner character varying(255) NOT NULL,
    path character varying(1000) NOT NULL,
    repo character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    github_token text
);

ALTER TABLE ONLY ${tenantSchema}.github_sbom_sources FORCE ROW LEVEL SECURITY;


--
-- Name: ingestion_jobs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ingestion_jobs (
    id uuid NOT NULL,
    job_type character varying(80) NOT NULL,
    source_type character varying(80) NOT NULL,
    asset_identifier character varying(500) NOT NULL,
    status character varying(32) NOT NULL,
    requested_by character varying(255),
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    dedupe_key character varying(700) NOT NULL,
    payload_json text,
    result_json text,
    failure_code character varying(120),
    failure_message text,
    visible_at timestamp with time zone DEFAULT now() NOT NULL,
    sbom_upload_id uuid,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT ingestion_jobs_status_check CHECK (((status)::text = ANY ((ARRAY['QUEUED'::character varying, 'RUNNING'::character varying, 'SUCCEEDED'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.ingestion_jobs FORCE ROW LEVEL SECURITY;


--
-- Name: inventory_component_cpe_map; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.inventory_component_cpe_map (
    id uuid NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    observed_version character varying(255),
    component_id uuid NOT NULL,
    cpe_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map FORCE ROW LEVEL SECURITY;


--
-- Name: inventory_components; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.inventory_components (
    id uuid NOT NULL,
    component_digest character varying(255),
    component_status character varying(255) NOT NULL,
    coord_key character varying(255),
    ecosystem character varying(255) NOT NULL,
    eol_checked_at timestamp with time zone,
    eol_cycle character varying(255),
    eol_date date,
    eol_slug character varying(255),
    eol_support_end_date date,
    ingested_at timestamp with time zone NOT NULL,
    is_eol boolean,
    last_observed_at timestamp with time zone NOT NULL,
    normalized_name character varying(255),
    normalized_purl character varying(255),
    normalized_version character varying(255),
    package_name character varying(255) NOT NULL,
    purl character varying(255) NOT NULL,
    retired_at timestamp with time zone,
    support_phase character varying(255),
    version character varying(255),
    asset_id uuid NOT NULL,
    sbom_upload_id uuid NOT NULL,
    software_identity_id uuid,
    manual_identity_id uuid,
    manual_identity_reason character varying(400),
    manual_identity_confirmed_by character varying(255),
    manual_identity_confirmed_at timestamp with time zone,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    package_group character varying(255),
    license text,
    scope character varying(30),
    CONSTRAINT inventory_components_component_status_check CHECK (((component_status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'RETIRED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.inventory_components FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_activities; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.investigation_activities (
    id bigint NOT NULL,
    activity_type character varying(50) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    description text,
    metadata text,
    performed_by character varying(100),
    investigation_id bigint NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.investigation_activities FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_activities_id_seq; Type: SEQUENCE; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigation_activities ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME ${tenantSchema}.investigation_activities_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: investigation_attachments; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.investigation_attachments (
    id bigint NOT NULL,
    file_name character varying(255) NOT NULL,
    file_size bigint,
    file_type character varying(100),
    storage_path character varying(500) NOT NULL,
    uploaded_at timestamp with time zone NOT NULL,
    uploaded_by character varying(100),
    investigation_id bigint NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.investigation_attachments FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_attachments_id_seq; Type: SEQUENCE; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigation_attachments ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME ${tenantSchema}.investigation_attachments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: investigation_runbook; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.investigation_runbook (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    cve_external_id character varying(50) NOT NULL,
    task_states jsonb DEFAULT '[]'::jsonb NOT NULL,
    agent_suggestions jsonb DEFAULT '{}'::jsonb NOT NULL,
    fp_overrides jsonb DEFAULT '[]'::jsonb NOT NULL,
    log_entries jsonb DEFAULT '[]'::jsonb NOT NULL,
    lead_analyst character varying(100),
    agent_confidence jsonb,
    agent_run_meta jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.investigation_runbook FORCE ROW LEVEL SECURITY;


--
-- Name: investigations; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.investigations (
    id bigint NOT NULL,
    assigned_to character varying(100),
    business_impact text,
    closed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    created_by character varying(100),
    exploit_available boolean,
    exploit_details text,
    mitigation_steps text,
    modified_by character varying(100),
    notes text,
    patch_available boolean,
    patch_details text,
    priority character varying(20),
    status character varying(50) NOT NULL,
    systems_affected text,
    updated_at timestamp with time zone NOT NULL,
    vuln_references text,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    vulnerability_id uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.investigations FORCE ROW LEVEL SECURITY;


--
-- Name: investigations_id_seq; Type: SEQUENCE; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigations ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME ${tenantSchema}.investigations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: org_cve_ai_artifacts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.org_cve_ai_artifacts (
    org_cve_record_id uuid NOT NULL,
    ai_actions_generated_at timestamp with time zone,
    ai_actions_json jsonb,
    ai_solution_generated_at timestamp with time zone,
    ai_solution_json jsonb,
    created_at timestamp with time zone NOT NULL,
    investigation_summary_generated_at timestamp with time zone,
    investigation_summary_input_json jsonb,
    investigation_summary_mode character varying(255),
    investigation_summary_output_json jsonb,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.org_cve_ai_artifacts FORCE ROW LEVEL SECURITY;


--
-- Name: org_cve_records; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.org_cve_records (
    id uuid NOT NULL,
    applicability_state character varying(255) NOT NULL,
    applicable_component_count bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    cvss_score double precision,
    eol_component_count bigint NOT NULL,
    eos_component_count bigint NOT NULL,
    epss_score double precision,
    external_id character varying(255) NOT NULL,
    fixed_component_count bigint NOT NULL,
    impact_reason character varying(255),
    impact_state character varying(255) NOT NULL,
    impacted boolean NOT NULL,
    impacted_component_count bigint NOT NULL,
    in_kev boolean NOT NULL,
    last_evaluated_at timestamp with time zone NOT NULL,
    matched_asset_count bigint NOT NULL,
    matched_component_count bigint NOT NULL,
    matched_software_count bigint NOT NULL,
    no_patch_component_count bigint NOT NULL,
    not_affected_component_count bigint NOT NULL,
    org_impact character varying(255),
    review_reason character varying(255),
    severity character varying(255) NOT NULL,
    suppressed_at timestamp with time zone,
    suppressed_by character varying(255),
    suppressed_by_rule_id uuid,
    suppressed_by_rule_name character varying(255),
    suppressed_until timestamp with time zone,
    suppression_justification character varying(255),
    suppression_reason character varying(255),
    under_investigation_component_count bigint NOT NULL,
    unknown_component_count bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    vuln_status character varying(255),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    CONSTRAINT org_cve_records_applicability_state_check CHECK (((applicability_state)::text = ANY ((ARRAY['APPLICABLE'::character varying, 'NOT_APPLICABLE'::character varying, 'UNKNOWN'::character varying])::text[]))),
    CONSTRAINT org_cve_records_impact_state_check CHECK (((impact_state)::text = ANY ((ARRAY['IMPACTED'::character varying, 'NOT_IMPACTED'::character varying, 'FIXED'::character varying, 'NO_PATCH'::character varying, 'UNDER_INVESTIGATION'::character varying, 'UNKNOWN'::character varying])::text[]))),
    CONSTRAINT org_cve_records_org_impact_check CHECK (((org_impact)::text = ANY ((ARRAY['NONE'::character varying, 'LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.org_cve_records FORCE ROW LEVEL SECURITY;


--
-- Name: ownership_rules; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.ownership_rules (
    id uuid NOT NULL,
    condition_json text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    execution_order integer NOT NULL,
    name character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_group character varying(255) NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.ownership_rules FORCE ROW LEVEL SECURITY;


--
-- Name: quality_issue_projection; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.quality_issue_projection (
    id text NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
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
    affects_active_findings boolean DEFAULT false NOT NULL,
    affected_asset_count bigint DEFAULT 0 NOT NULL,
    affected_component_count bigint DEFAULT 0 NOT NULL,
    open_finding_count bigint DEFAULT 0 NOT NULL,
    open_vulnerability_count bigint DEFAULT 0 NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_computed_at timestamp with time zone DEFAULT now() NOT NULL,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    drilldown_json jsonb DEFAULT '[]'::jsonb NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.quality_issue_projection FORCE ROW LEVEL SECURITY;


--
-- Name: risk_policies; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.risk_policies (
    id uuid NOT NULL,
    asset_critical_sla_multiplier double precision NOT NULL,
    asset_high_sla_multiplier double precision NOT NULL,
    asset_low_sla_multiplier double precision NOT NULL,
    asset_medium_sla_multiplier double precision NOT NULL,
    auto_close_after_days integer NOT NULL,
    auto_close_asset_identifier character varying(255),
    auto_close_asset_retired_enabled boolean DEFAULT true NOT NULL,
    auto_close_component_removed_enabled boolean DEFAULT true NOT NULL,
    auto_close_duplicate_enabled boolean DEFAULT true NOT NULL,
    auto_close_enabled boolean NOT NULL,
    auto_close_not_observed_enabled boolean DEFAULT true NOT NULL,
    auto_close_required_consecutive_misses integer DEFAULT 2 NOT NULL,
    auto_close_run_interval_days integer DEFAULT 1 NOT NULL,
    auto_close_last_run_at timestamp with time zone,
    auto_close_source_disabled_enabled boolean DEFAULT false NOT NULL,
    critical_sla_days integer NOT NULL,
    critical_threshold double precision NOT NULL,
    finding_generation_mode character varying(20) NOT NULL,
    findings_score_config jsonb,
    high_sla_days integer NOT NULL,
    high_threshold double precision NOT NULL,
    low_sla_days integer NOT NULL,
    medium_sla_days integer NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    copilot_enabled boolean DEFAULT false NOT NULL,
    copilot_shadow_mode boolean DEFAULT true NOT NULL,
    copilot_auto_run boolean DEFAULT false NOT NULL,
    agent_auto_threshold double precision DEFAULT 0.85 NOT NULL,
    agent_review_threshold double precision DEFAULT 0.60 NOT NULL,
    agent_max_concurrent integer DEFAULT 10 NOT NULL,
    CONSTRAINT risk_policies_finding_generation_mode_check CHECK (((finding_generation_mode)::text = ANY ((ARRAY['AUTO'::character varying, 'MANUAL'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.risk_policies FORCE ROW LEVEL SECURITY;


--
-- Name: sbom_uploads; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.sbom_uploads (
    id uuid NOT NULL,
    asset_id uuid,
    component_count integer,
    content_length_bytes bigint,
    content_sha256 character varying(255),
    content_type character varying(255),
    evidence_json text,
    fetch_status_code integer,
    findings_generated integer,
    format character varying(255) NOT NULL,
    ingestion_source_system character varying(255),
    ingestion_source_type character varying(255),
    original_filename character varying(255) NOT NULL,
    source_endpoint character varying(255),
    source_reference character varying(255),
    status character varying(255) NOT NULL,
    uploaded_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT sbom_uploads_format_check CHECK (((format)::text = ANY ((ARRAY['CYCLONEDX'::character varying, 'SPDX'::character varying, 'HOST_INVENTORY'::character varying, 'UNKNOWN'::character varying])::text[]))),
    CONSTRAINT sbom_uploads_status_check CHECK (((status)::text = ANY ((ARRAY['IN_PROGRESS'::character varying, 'SUCCESS'::character varying, 'FAILURE'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.sbom_uploads FORCE ROW LEVEL SECURITY;


--
-- Name: sccm_cmdb_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.sccm_cmdb_configs (
    id uuid NOT NULL,
    auth_type character varying(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    credential_secret character varying(255),
    database_name character varying(255) NOT NULL,
    enabled boolean NOT NULL,
    fetch_size integer NOT NULL,
    interval_minutes integer NOT NULL,
    jdbc_url character varying(255),
    last_sync_at timestamp with time zone,
    last_test_message character varying(255),
    last_test_status character varying(255),
    last_tested_at timestamp with time zone,
    mock_mode boolean NOT NULL,
    query_timeout_seconds integer NOT NULL,
    site_code character varying(255),
    source_system character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    username character varying(255),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT sccm_cmdb_configs_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['SQL_AUTH'::character varying, 'WINDOWS_AUTH'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.sccm_cmdb_configs FORCE ROW LEVEL SECURITY;


--
-- Name: service_accounts; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.service_accounts (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    key_id character varying(255) NOT NULL,
    last_used_at timestamp with time zone,
    name character varying(255) NOT NULL,
    role character varying(255) NOT NULL,
    status character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.service_accounts FORCE ROW LEVEL SECURITY;


--
-- Name: servicenow_cmdb_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.servicenow_cmdb_configs (
    id uuid NOT NULL,
    auth_type character varying(255) NOT NULL,
    auto_sync_enabled boolean NOT NULL,
    base_url character varying(255),
    ci_table character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    credential_secret character varying(255),
    discovery_fields character varying(4000),
    discovery_model_table character varying(255) NOT NULL,
    discovery_query character varying(4000),
    enabled boolean NOT NULL,
    install_fields character varying(4000),
    install_query character varying(4000),
    install_table character varying(255) NOT NULL,
    interval_minutes integer NOT NULL,
    last_sync_at timestamp with time zone,
    last_test_message character varying(2000),
    last_test_status character varying(255),
    last_tested_at timestamp with time zone,
    page_size integer NOT NULL,
    source_system character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    username character varying(255),
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT servicenow_cmdb_configs_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['BASIC'::character varying, 'BEARER'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.servicenow_cmdb_configs FORCE ROW LEVEL SECURITY;


--
-- Name: software_identity_cluster_link; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.software_identity_cluster_link (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    source_type character varying(40) NOT NULL,
    source_key character varying(500) NOT NULL,
    target_identity_id uuid NOT NULL,
    apply_to_future boolean DEFAULT true NOT NULL,
    reason character varying(400),
    confirmed_by character varying(255),
    confirmed_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by character varying(255)
);

ALTER TABLE ONLY ${tenantSchema}.software_identity_cluster_link FORCE ROW LEVEL SECURITY;


--
-- Name: software_identity_metadata; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.software_identity_metadata (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    software_identity_id uuid NOT NULL,
    owner text,
    licensed text DEFAULT 'Unknown'::text NOT NULL,
    license_type text,
    support_group text,
    recommendation text,
    recommendation_updated_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.software_identity_metadata FORCE ROW LEVEL SECURITY;


--
-- Name: software_identity_summary; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.software_identity_summary (
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    software_identity_id uuid NOT NULL,
    display_name text,
    canonical_key text,
    vendor text,
    product text,
    normalized_key text NOT NULL,
    purl text,
    cpe23 text,
    asset_types text[] DEFAULT '{}'::text[] NOT NULL,
    ecosystems text[] DEFAULT '{}'::text[] NOT NULL,
    source_systems text[] DEFAULT '{}'::text[] NOT NULL,
    eol_slug text,
    mapping_confirmed boolean DEFAULT false NOT NULL,
    needs_eol_mapping boolean DEFAULT false NOT NULL,
    asset_count bigint DEFAULT 0 NOT NULL,
    component_count bigint DEFAULT 0 NOT NULL,
    version_count bigint DEFAULT 0 NOT NULL,
    eol_component_count bigint DEFAULT 0 NOT NULL,
    near_eol_component_count bigint DEFAULT 0 NOT NULL,
    unknown_eol_component_count bigint DEFAULT 0 NOT NULL,
    last_observed_at timestamp with time zone,
    summary_updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.software_identity_summary FORCE ROW LEVEL SECURITY;


--
-- Name: software_instances; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.software_instances (
    id uuid NOT NULL,
    active_install boolean,
    created_at timestamp with time zone NOT NULL,
    discovery_model_pk character varying(500),
    display_name character varying(500) NOT NULL,
    eol_checked_at timestamp with time zone,
    eol_cycle character varying(100),
    eol_date date,
    eol_slug character varying(200),
    eol_support_end_date date,
    install_date timestamp with time zone,
    is_eol boolean,
    last_scanned timestamp with time zone,
    last_used timestamp with time zone,
    normalized_product character varying(255) NOT NULL,
    normalized_publisher character varying(255),
    normalized_version character varying(255),
    publisher character varying(255),
    source_system character varying(64) NOT NULL,
    support_phase character varying(30),
    unlicensed_install boolean,
    updated_at timestamp with time zone NOT NULL,
    version character varying(255),
    version_evidence character varying(1000),
    ci_id uuid NOT NULL,
    discovery_model_id uuid,
    inventory_component_id uuid,
    software_identity_id uuid,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.software_instances FORCE ROW LEVEL SECURITY;


--
-- Name: software_inventory_items; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.software_inventory_items (
    id uuid NOT NULL,
    component_status character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    ecosystem character varying(255) NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone,
    package_name character varying(255) NOT NULL,
    purl character varying(255) NOT NULL,
    synced_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version character varying(255) NOT NULL,
    asset_id uuid,
    component_id uuid NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items FORCE ROW LEVEL SECURITY;


--
-- Name: suppression_rules; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.suppression_rules (
    id uuid NOT NULL,
    condition_logic character varying(255) NOT NULL,
    conditions_json jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name character varying(255) NOT NULL,
    reason character varying(255),
    record_type character varying(255) NOT NULL,
    state character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL,
    CONSTRAINT suppression_rules_record_type_check CHECK (((record_type)::text = ANY ((ARRAY['CVE'::character varying, 'FINDING'::character varying])::text[]))),
    CONSTRAINT suppression_rules_state_check CHECK (((state)::text = ANY ((ARRAY['DRAFT'::character varying, 'APPROVED'::character varying, 'IN_REVIEW'::character varying, 'REJECTED'::character varying, 'EXPIRED'::character varying])::text[])))
);

ALTER TABLE ONLY ${tenantSchema}.suppression_rules FORCE ROW LEVEL SECURITY;


--
-- Name: vulnerability_source_filter_configs; Type: TABLE; Schema: ${tenantSchema}; Owner: -
--

CREATE TABLE ${tenantSchema}.vulnerability_source_filter_configs (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    enabled_for_correlation boolean NOT NULL,
    filters_json text,
    source_system character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid NOT NULL
);

ALTER TABLE ONLY ${tenantSchema}.vulnerability_source_filter_configs FORCE ROW LEVEL SECURITY;


--
-- Name: ai_grid_artifact_classifications ai_grid_artifact_classificati_tenant_id_artifact_id_technol_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_artifact_classifications
    ADD CONSTRAINT ai_grid_artifact_classificati_tenant_id_artifact_id_technol_key UNIQUE (tenant_id, artifact_id, technology_id, capability);


--
-- Name: ai_grid_artifact_classifications ai_grid_artifact_classifications_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_artifact_classifications
    ADD CONSTRAINT ai_grid_artifact_classifications_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_assessments ai_grid_assessments_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_assessments
    ADD CONSTRAINT ai_grid_assessments_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_assessments ai_grid_assessments_tenant_id_run_id_policy_id_subject_type_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_assessments
    ADD CONSTRAINT ai_grid_assessments_tenant_id_run_id_policy_id_subject_type_key UNIQUE (tenant_id, run_id, policy_id, subject_type, subject_id);


--
-- Name: ai_grid_budget_admissions ai_grid_budget_admissions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_admissions
    ADD CONSTRAINT ai_grid_budget_admissions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_budget_admissions ai_grid_budget_admissions_tenant_id_run_id_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_admissions
    ADD CONSTRAINT ai_grid_budget_admissions_tenant_id_run_id_key UNIQUE (tenant_id, run_id);


--
-- Name: ai_grid_budget_alerts ai_grid_budget_alerts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_alerts
    ADD CONSTRAINT ai_grid_budget_alerts_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_budget_config ai_grid_budget_config_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_config
    ADD CONSTRAINT ai_grid_budget_config_pkey PRIMARY KEY (tenant_id);


--
-- Name: ai_grid_capability_observations ai_grid_capability_observatio_tenant_id_run_id_provider_cap_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_capability_observations
    ADD CONSTRAINT ai_grid_capability_observatio_tenant_id_run_id_provider_cap_key UNIQUE (tenant_id, run_id, provider, capability_id, account_id, region);


--
-- Name: ai_grid_capability_observations ai_grid_capability_observations_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_capability_observations
    ADD CONSTRAINT ai_grid_capability_observations_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_coverage_gaps ai_grid_coverage_gaps_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_coverage_gaps
    ADD CONSTRAINT ai_grid_coverage_gaps_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_coverage_gaps ai_grid_coverage_gaps_tenant_id_fingerprint_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_coverage_gaps
    ADD CONSTRAINT ai_grid_coverage_gaps_tenant_id_fingerprint_key UNIQUE (tenant_id, fingerprint);


--
-- Name: ai_grid_current_coverage_artifacts ai_grid_current_coverage_artifacts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_artifacts
    ADD CONSTRAINT ai_grid_current_coverage_artifacts_pkey PRIMARY KEY (tenant_id, artifact_id);


--
-- Name: ai_grid_current_coverage_state ai_grid_current_coverage_state_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_state
    ADD CONSTRAINT ai_grid_current_coverage_state_pkey PRIMARY KEY (tenant_id);


--
-- Name: ai_grid_current_expected_candidates ai_grid_current_expected_candidates_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_expected_candidates
    ADD CONSTRAINT ai_grid_current_expected_candidates_pkey PRIMARY KEY (tenant_id, artifact_id, policy_id);


--
-- Name: ai_grid_evidence_holds ai_grid_evidence_holds_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_evidence_holds
    ADD CONSTRAINT ai_grid_evidence_holds_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_evidence_holds ai_grid_evidence_holds_tenant_id_snapshot_body_id_hold_type_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_evidence_holds
    ADD CONSTRAINT ai_grid_evidence_holds_tenant_id_snapshot_body_id_hold_type_key UNIQUE (tenant_id, snapshot_body_id, hold_type, reference_id);


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_tenant_id_exposure_path_id_sy_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_tenant_id_exposure_path_id_sy_key UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, system_id, artifact_id, association_role);


--
-- Name: ai_grid_exposure_dispositions ai_grid_exposure_dispositions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_dispositions
    ADD CONSTRAINT ai_grid_exposure_dispositions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_exposure_executions ai_grid_exposure_executions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_executions
    ADD CONSTRAINT ai_grid_exposure_executions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_exposure_executions ai_grid_exposure_executions_tenant_id_coverage_epoch_id_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_executions
    ADD CONSTRAINT ai_grid_exposure_executions_tenant_id_coverage_epoch_id_key UNIQUE (tenant_id, coverage_epoch_id);


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_exposure_paths ai_grid_exposure_paths_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths
    ADD CONSTRAINT ai_grid_exposure_paths_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_exposure_paths ai_grid_exposure_paths_tenant_id_fingerprint_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths
    ADD CONSTRAINT ai_grid_exposure_paths_tenant_id_fingerprint_key UNIQUE (tenant_id, fingerprint);


--
-- Name: ai_grid_facts ai_grid_facts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts
    ADD CONSTRAINT ai_grid_facts_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_facts ai_grid_facts_tenant_id_run_id_artifact_id_fact_key_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts
    ADD CONSTRAINT ai_grid_facts_tenant_id_run_id_artifact_id_fact_key_key UNIQUE (tenant_id, run_id, artifact_id, fact_key);


--
-- Name: ai_grid_host_context_facts ai_grid_host_context_facts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_host_context_facts
    ADD CONSTRAINT ai_grid_host_context_facts_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_host_context_facts ai_grid_host_context_facts_tenant_id_artifact_id_fact_key_s_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_host_context_facts
    ADD CONSTRAINT ai_grid_host_context_facts_tenant_id_artifact_id_fact_key_s_key UNIQUE (tenant_id, artifact_id, fact_key, source_port, observed_at);


--
-- Name: ai_grid_outbox ai_grid_outbox_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_outbox
    ADD CONSTRAINT ai_grid_outbox_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_outbox ai_grid_outbox_tenant_id_event_type_aggregate_id_aggregate__key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_outbox
    ADD CONSTRAINT ai_grid_outbox_tenant_id_event_type_aggregate_id_aggregate__key UNIQUE (tenant_id, event_type, aggregate_id, aggregate_version);


--
-- Name: ai_grid_owner_history ai_grid_owner_history_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_owner_history
    ADD CONSTRAINT ai_grid_owner_history_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_artifact_overrides ai_grid_policy_artifact_overr_tenant_id_policy_id_artifact__key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_artifact_overrides
    ADD CONSTRAINT ai_grid_policy_artifact_overr_tenant_id_policy_id_artifact__key UNIQUE (tenant_id, policy_id, artifact_id);


--
-- Name: ai_grid_policy_artifact_overrides ai_grid_policy_artifact_overrides_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_artifact_overrides
    ADD CONSTRAINT ai_grid_policy_artifact_overrides_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_parameters ai_grid_policy_parameters_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_parameters
    ADD CONSTRAINT ai_grid_policy_parameters_pkey PRIMARY KEY (policy_id);


--
-- Name: ai_grid_policy_readiness ai_grid_policy_readiness_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_readiness
    ADD CONSTRAINT ai_grid_policy_readiness_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_readiness ai_grid_policy_readiness_tenant_id_run_id_policy_id_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_readiness
    ADD CONSTRAINT ai_grid_policy_readiness_tenant_id_run_id_policy_id_key UNIQUE (tenant_id, run_id, policy_id);


--
-- Name: ai_grid_policy_scopes ai_grid_policy_scopes_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_scopes
    ADD CONSTRAINT ai_grid_policy_scopes_pkey PRIMARY KEY (policy_id);


--
-- Name: ai_grid_policy_selection_history ai_grid_policy_selection_history_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selection_history
    ADD CONSTRAINT ai_grid_policy_selection_history_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_selections ai_grid_policy_selections_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selections
    ADD CONSTRAINT ai_grid_policy_selections_pkey PRIMARY KEY (policy_id);


--
-- Name: ai_grid_relationship_snapshots ai_grid_relationship_snapshot_tenant_id_run_id_source_artif_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots
    ADD CONSTRAINT ai_grid_relationship_snapshot_tenant_id_run_id_source_artif_key UNIQUE (tenant_id, run_id, source_artifact_id, target_artifact_id, relationship_type);


--
-- Name: ai_grid_relationship_snapshots ai_grid_relationship_snapshots_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots
    ADD CONSTRAINT ai_grid_relationship_snapshots_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_retention_decisions ai_grid_retention_decisions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_decisions
    ADD CONSTRAINT ai_grid_retention_decisions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_retention_decisions ai_grid_retention_decisions_tenant_id_snapshot_body_id_eval_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_decisions
    ADD CONSTRAINT ai_grid_retention_decisions_tenant_id_snapshot_body_id_eval_key UNIQUE (tenant_id, snapshot_body_id, evaluated_at);


--
-- Name: ai_grid_retention_policies ai_grid_retention_policies_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_policies
    ADD CONSTRAINT ai_grid_retention_policies_pkey PRIMARY KEY (retention_class);


--
-- Name: ai_grid_retention_purge_audit ai_grid_retention_purge_audit_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_purge_audit
    ADD CONSTRAINT ai_grid_retention_purge_audit_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_run_metrics ai_grid_run_metrics_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_metrics
    ADD CONSTRAINT ai_grid_run_metrics_pkey PRIMARY KEY (run_id);


--
-- Name: ai_grid_run_scope_metrics ai_grid_run_scope_metrics_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_scope_metrics
    ADD CONSTRAINT ai_grid_run_scope_metrics_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_run_scope_metrics ai_grid_run_scope_metrics_tenant_id_run_id_scope_key_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_scope_metrics
    ADD CONSTRAINT ai_grid_run_scope_metrics_tenant_id_run_id_scope_key_key UNIQUE (tenant_id, run_id, scope_key);


--
-- Name: ai_grid_scan_cadence_rules ai_grid_scan_cadence_rules_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_scan_cadence_rules
    ADD CONSTRAINT ai_grid_scan_cadence_rules_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_scan_cadence_rules ai_grid_scan_cadence_rules_tenant_id_provider_resource_fami_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_scan_cadence_rules
    ADD CONSTRAINT ai_grid_scan_cadence_rules_tenant_id_provider_resource_fami_key UNIQUE (tenant_id, provider, resource_family, environment, criticality);


--
-- Name: ai_grid_setup_actions ai_grid_setup_actions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_setup_actions
    ADD CONSTRAINT ai_grid_setup_actions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_setup_actions ai_grid_setup_actions_tenant_id_fingerprint_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_setup_actions
    ADD CONSTRAINT ai_grid_setup_actions_tenant_id_fingerprint_key UNIQUE (tenant_id, fingerprint);


--
-- Name: ai_grid_snapshot_bodies ai_grid_snapshot_bodies_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_bodies
    ADD CONSTRAINT ai_grid_snapshot_bodies_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_snapshot_bodies ai_grid_snapshot_bodies_tenant_id_content_hash_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_bodies
    ADD CONSTRAINT ai_grid_snapshot_bodies_tenant_id_content_hash_key UNIQUE (tenant_id, content_hash);


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_tenant_id_run_id_artifact_id_sco_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_tenant_id_run_id_artifact_id_sco_key UNIQUE (tenant_id, run_id, artifact_id, scope_key);


--
-- Name: ai_grid_system_lineage_events ai_grid_system_lineage_events_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_events
    ADD CONSTRAINT ai_grid_system_lineage_events_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_partic_tenant_id_event_id_system_id__key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_partic_tenant_id_event_id_system_id__key UNIQUE (tenant_id, event_id, system_id, participant_role);


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_participants_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_participants_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_system_membership_decisions ai_grid_system_membership_decisions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions
    ADD CONSTRAINT ai_grid_system_membership_decisions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_system_membership_overrides ai_grid_system_membership_overrides_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_overrides
    ADD CONSTRAINT ai_grid_system_membership_overrides_pkey PRIMARY KEY (tenant_id, system_id, artifact_id);


--
-- Name: ai_grid_system_memberships ai_grid_system_memberships_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships
    ADD CONSTRAINT ai_grid_system_memberships_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_system_memberships ai_grid_system_memberships_tenant_id_system_revision_id_art_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships
    ADD CONSTRAINT ai_grid_system_memberships_tenant_id_system_revision_id_art_key UNIQUE (tenant_id, system_revision_id, artifact_id);


--
-- Name: ai_grid_system_revisions ai_grid_system_revisions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_revisions
    ADD CONSTRAINT ai_grid_system_revisions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_system_revisions ai_grid_system_revisions_tenant_id_system_id_revision_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_revisions
    ADD CONSTRAINT ai_grid_system_revisions_tenant_id_system_id_revision_key UNIQUE (tenant_id, system_id, revision);


--
-- Name: ai_grid_systems ai_grid_systems_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_systems
    ADD CONSTRAINT ai_grid_systems_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_systems ai_grid_systems_tenant_id_stable_key_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_systems
    ADD CONSTRAINT ai_grid_systems_tenant_id_stable_key_key UNIQUE (tenant_id, stable_key);


--
-- Name: ai_security_artifact_sources ai_security_artifact_sources_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources
    ADD CONSTRAINT ai_security_artifact_sources_pkey PRIMARY KEY (id);


--
-- Name: ai_security_artifact_sources ai_security_artifact_sources_tenant_id_artifact_id_scope_ke_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources
    ADD CONSTRAINT ai_security_artifact_sources_tenant_id_artifact_id_scope_ke_key UNIQUE (tenant_id, artifact_id, scope_key);


--
-- Name: ai_security_artifacts ai_security_artifacts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifacts
    ADD CONSTRAINT ai_security_artifacts_pkey PRIMARY KEY (id);


--
-- Name: ai_security_artifacts ai_security_artifacts_tenant_id_provider_provider_resource__key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifacts
    ADD CONSTRAINT ai_security_artifacts_tenant_id_provider_provider_resource__key UNIQUE (tenant_id, provider, provider_resource_id);


--
-- Name: ai_security_azure_credential_profiles ai_security_azure_credential_profiles_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_azure_credential_profiles
    ADD CONSTRAINT ai_security_azure_credential_profiles_pkey PRIMARY KEY (id);


--
-- Name: ai_security_azure_credential_profiles ai_security_azure_credential_profiles_tenant_id_name_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_azure_credential_profiles
    ADD CONSTRAINT ai_security_azure_credential_profiles_tenant_id_name_key UNIQUE (tenant_id, name);


--
-- Name: ai_security_connector_configs ai_security_connector_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_connector_configs
    ADD CONSTRAINT ai_security_connector_configs_pkey PRIMARY KEY (id);


--
-- Name: ai_security_connector_configs ai_security_connector_configs_tenant_id_provider_account_id_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_connector_configs
    ADD CONSTRAINT ai_security_connector_configs_tenant_id_provider_account_id_key UNIQUE (tenant_id, provider, account_id);


--
-- Name: ai_security_observation_receipts ai_security_observation_recei_tenant_id_run_id_scope_key_ch_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_observation_receipts
    ADD CONSTRAINT ai_security_observation_recei_tenant_id_run_id_scope_key_ch_key UNIQUE (tenant_id, run_id, scope_key, chunk_sequence);


--
-- Name: ai_security_observation_receipts ai_security_observation_receipts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_observation_receipts
    ADD CONSTRAINT ai_security_observation_receipts_pkey PRIMARY KEY (id);


--
-- Name: ai_security_observation_receipts ai_security_observation_receipts_tenant_id_idempotency_key_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_observation_receipts
    ADD CONSTRAINT ai_security_observation_receipts_tenant_id_idempotency_key_key UNIQUE (tenant_id, idempotency_key);


--
-- Name: ai_security_relationships ai_security_relationships_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships
    ADD CONSTRAINT ai_security_relationships_pkey PRIMARY KEY (id);


--
-- Name: ai_security_relationships ai_security_relationships_tenant_id_source_artifact_id_targ_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships
    ADD CONSTRAINT ai_security_relationships_tenant_id_source_artifact_id_targ_key UNIQUE (tenant_id, source_artifact_id, target_artifact_id, relationship_type);


--
-- Name: ai_security_snapshot_scopes ai_security_snapshot_scopes_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_snapshot_scopes
    ADD CONSTRAINT ai_security_snapshot_scopes_pkey PRIMARY KEY (id);


--
-- Name: ai_security_snapshot_scopes ai_security_snapshot_scopes_tenant_id_run_id_scope_key_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_snapshot_scopes
    ADD CONSTRAINT ai_security_snapshot_scopes_tenant_id_run_id_scope_key_key UNIQUE (tenant_id, run_id, scope_key);


--
-- Name: applicability_assessments applicability_assessments_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.applicability_assessments
    ADD CONSTRAINT applicability_assessments_pkey PRIMARY KEY (id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: aws_discovery_configs aws_discovery_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_configs
    ADD CONSTRAINT aws_discovery_configs_pkey PRIMARY KEY (id);


--
-- Name: aws_discovery_targets aws_discovery_targets_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_targets
    ADD CONSTRAINT aws_discovery_targets_pkey PRIMARY KEY (id);


--
-- Name: azure_discovery_configs azure_discovery_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_configs
    ADD CONSTRAINT azure_discovery_configs_pkey PRIMARY KEY (id);


--
-- Name: azure_discovery_targets azure_discovery_targets_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_targets
    ADD CONSTRAINT azure_discovery_targets_pkey PRIMARY KEY (id);


--
-- Name: bom_component_evidence bom_component_evidence_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_evidence
    ADD CONSTRAINT bom_component_evidence_pkey PRIMARY KEY (id);


--
-- Name: bom_component_vulnerability_links bom_component_vulnerability_links_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_vulnerability_links
    ADD CONSTRAINT bom_component_vulnerability_links_pkey PRIMARY KEY (id);


--
-- Name: bom_component_workflows bom_component_workflows_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_workflows
    ADD CONSTRAINT bom_component_workflows_pkey PRIMARY KEY (id);


--
-- Name: bom_components bom_components_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_components
    ADD CONSTRAINT bom_components_pkey PRIMARY KEY (id);


--
-- Name: bom_ingestion_records bom_ingestion_records_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_ingestion_records
    ADD CONSTRAINT bom_ingestion_records_pkey PRIMARY KEY (id);


--
-- Name: campaign_activities campaign_activities_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_activities
    ADD CONSTRAINT campaign_activities_pkey PRIMARY KEY (id);


--
-- Name: campaign_delivery_attempts campaign_delivery_attempts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_delivery_attempts
    ADD CONSTRAINT campaign_delivery_attempts_pkey PRIMARY KEY (id);


--
-- Name: campaign_exceptions campaign_exceptions_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_exceptions
    ADD CONSTRAINT campaign_exceptions_pkey PRIMARY KEY (id);


--
-- Name: campaign_notes campaign_notes_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notes
    ADD CONSTRAINT campaign_notes_pkey PRIMARY KEY (id);


--
-- Name: campaign_notify_groups campaign_notify_groups_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notify_groups
    ADD CONSTRAINT campaign_notify_groups_pkey PRIMARY KEY (id);


--
-- Name: campaign_vulnerabilities campaign_vulnerabilities_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities
    ADD CONSTRAINT campaign_vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: campaign_watchlist_entries campaign_watchlist_entries_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_watchlist_entries
    ADD CONSTRAINT campaign_watchlist_entries_pkey PRIMARY KEY (id);


--
-- Name: campaigns campaigns_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (id);


--
-- Name: cbom_components cbom_components_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_components
    ADD CONSTRAINT cbom_components_pkey PRIMARY KEY (id);


--
-- Name: cbom_components cbom_components_tenant_id_source_bom_id_component_fingerpri_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_components
    ADD CONSTRAINT cbom_components_tenant_id_source_bom_id_component_fingerpri_key UNIQUE (tenant_id, source_bom_id, component_fingerprint);


--
-- Name: cbom_posture_summary cbom_posture_summary_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary
    ADD CONSTRAINT cbom_posture_summary_pkey PRIMARY KEY (id);


--
-- Name: cbom_posture_summary cbom_posture_summary_tenant_id_asset_id_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary
    ADD CONSTRAINT cbom_posture_summary_tenant_id_asset_id_key UNIQUE (tenant_id, asset_id);


--
-- Name: cbom_risk_findings cbom_risk_findings_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_risk_findings
    ADD CONSTRAINT cbom_risk_findings_pkey PRIMARY KEY (id);


--
-- Name: cbom_risk_findings cbom_risk_findings_tenant_id_cbom_component_id_finding_fing_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_risk_findings
    ADD CONSTRAINT cbom_risk_findings_tenant_id_cbom_component_id_finding_fing_key UNIQUE (tenant_id, cbom_component_id, finding_fingerprint);


--
-- Name: ci_aliases ci_aliases_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ci_aliases
    ADD CONSTRAINT ci_aliases_pkey PRIMARY KEY (id);


--
-- Name: cis cis_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cis
    ADD CONSTRAINT cis_pkey PRIMARY KEY (id);


--
-- Name: component_vulnerability_states component_vulnerability_states_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states
    ADD CONSTRAINT component_vulnerability_states_pkey PRIMARY KEY (id);


--
-- Name: dashboard_noise_reduction_projection dashboard_noise_reduction_projection_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.dashboard_noise_reduction_projection
    ADD CONSTRAINT dashboard_noise_reduction_projection_pkey PRIMARY KEY (tenant_id);


--
-- Name: demo_invites demo_invites_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_invites
    ADD CONSTRAINT demo_invites_pkey PRIMARY KEY (id);


--
-- Name: demo_requests demo_requests_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_requests
    ADD CONSTRAINT demo_requests_pkey PRIMARY KEY (id);


--
-- Name: discovery_models discovery_models_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.discovery_models
    ADD CONSTRAINT discovery_models_pkey PRIMARY KEY (id);


--
-- Name: finding_comments finding_comments_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_comments
    ADD CONSTRAINT finding_comments_pkey PRIMARY KEY (id);


--
-- Name: finding_delta_queue finding_delta_queue_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_delta_queue
    ADD CONSTRAINT finding_delta_queue_pkey PRIMARY KEY (id);


--
-- Name: finding_events finding_events_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_events
    ADD CONSTRAINT finding_events_pkey PRIMARY KEY (id);


--
-- Name: finding_list_projection finding_list_projection_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_list_projection
    ADD CONSTRAINT finding_list_projection_pkey PRIMARY KEY (finding_id);


--
-- Name: finding_reviews finding_reviews_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_reviews
    ADD CONSTRAINT finding_reviews_pkey PRIMARY KEY (id);


--
-- Name: finding_subjects finding_subjects_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_subjects
    ADD CONSTRAINT finding_subjects_pkey PRIMARY KEY (id);


--
-- Name: finding_subjects finding_subjects_tenant_id_finding_id_subject_type_subject__key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_subjects
    ADD CONSTRAINT finding_subjects_tenant_id_finding_id_subject_type_subject__key UNIQUE (tenant_id, finding_id, subject_type, subject_id, subject_role);


--
-- Name: finding_workspace_projection_status finding_workspace_projection_status_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_workspace_projection_status
    ADD CONSTRAINT finding_workspace_projection_status_pkey PRIMARY KEY (projection_key);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: fix_records fix_records_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.fix_records
    ADD CONSTRAINT fix_records_pkey PRIMARY KEY (id);


--
-- Name: github_sbom_sources github_sbom_sources_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.github_sbom_sources
    ADD CONSTRAINT github_sbom_sources_pkey PRIMARY KEY (id);


--
-- Name: ingestion_jobs ingestion_jobs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ingestion_jobs
    ADD CONSTRAINT ingestion_jobs_pkey PRIMARY KEY (id);


--
-- Name: inventory_component_cpe_map inventory_component_cpe_map_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map
    ADD CONSTRAINT inventory_component_cpe_map_pkey PRIMARY KEY (id);


--
-- Name: inventory_components inventory_components_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT inventory_components_pkey PRIMARY KEY (id);


--
-- Name: investigation_activities investigation_activities_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_activities
    ADD CONSTRAINT investigation_activities_pkey PRIMARY KEY (id);


--
-- Name: investigation_attachments investigation_attachments_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_attachments
    ADD CONSTRAINT investigation_attachments_pkey PRIMARY KEY (id);


--
-- Name: investigation_runbook investigation_runbook_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_runbook
    ADD CONSTRAINT investigation_runbook_pkey PRIMARY KEY (id);


--
-- Name: investigations investigations_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigations
    ADD CONSTRAINT investigations_pkey PRIMARY KEY (id);


--
-- Name: org_cve_ai_artifacts org_cve_ai_artifacts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_ai_artifacts
    ADD CONSTRAINT org_cve_ai_artifacts_pkey PRIMARY KEY (org_cve_record_id);


--
-- Name: org_cve_records org_cve_records_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_records
    ADD CONSTRAINT org_cve_records_pkey PRIMARY KEY (id);


--
-- Name: ownership_rules ownership_rules_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ownership_rules
    ADD CONSTRAINT ownership_rules_pkey PRIMARY KEY (id);


--
-- Name: quality_issue_projection quality_issue_projection_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.quality_issue_projection
    ADD CONSTRAINT quality_issue_projection_pkey PRIMARY KEY (id);


--
-- Name: risk_policies risk_policies_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.risk_policies
    ADD CONSTRAINT risk_policies_pkey PRIMARY KEY (id);


--
-- Name: sbom_uploads sbom_uploads_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sbom_uploads
    ADD CONSTRAINT sbom_uploads_pkey PRIMARY KEY (id);


--
-- Name: sccm_cmdb_configs sccm_cmdb_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sccm_cmdb_configs
    ADD CONSTRAINT sccm_cmdb_configs_pkey PRIMARY KEY (id);


--
-- Name: service_accounts service_accounts_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);


--
-- Name: servicenow_cmdb_configs servicenow_cmdb_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.servicenow_cmdb_configs
    ADD CONSTRAINT servicenow_cmdb_configs_pkey PRIMARY KEY (id);


--
-- Name: software_identity_cluster_link software_identity_cluster_link_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_cluster_link
    ADD CONSTRAINT software_identity_cluster_link_pkey PRIMARY KEY (id);


--
-- Name: software_identity_metadata software_identity_metadata_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_metadata
    ADD CONSTRAINT software_identity_metadata_pkey PRIMARY KEY (tenant_id, software_identity_id);


--
-- Name: software_identity_summary software_identity_summary_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_summary
    ADD CONSTRAINT software_identity_summary_pkey PRIMARY KEY (tenant_id, software_identity_id);


--
-- Name: software_instances software_instances_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT software_instances_pkey PRIMARY KEY (id);


--
-- Name: software_inventory_items software_inventory_items_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items
    ADD CONSTRAINT software_inventory_items_pkey PRIMARY KEY (id);


--
-- Name: suppression_rules suppression_rules_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.suppression_rules
    ADD CONSTRAINT suppression_rules_pkey PRIMARY KEY (id);


--
-- Name: assets uk_assets_tenant_identifier; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.assets
    ADD CONSTRAINT uk_assets_tenant_identifier UNIQUE (tenant_id, identifier);


--
-- Name: aws_discovery_configs uk_aws_discovery_configs_tenant_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_configs
    ADD CONSTRAINT uk_aws_discovery_configs_tenant_source UNIQUE (tenant_id, source_system);


--
-- Name: aws_discovery_targets uk_aws_discovery_targets_config_account; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_targets
    ADD CONSTRAINT uk_aws_discovery_targets_config_account UNIQUE (config_id, account_id);


--
-- Name: azure_discovery_configs uk_azure_discovery_configs_tenant_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_configs
    ADD CONSTRAINT uk_azure_discovery_configs_tenant_source UNIQUE (tenant_id, source_system);


--
-- Name: azure_discovery_targets uk_azure_discovery_targets_config_subscription; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_targets
    ADD CONSTRAINT uk_azure_discovery_targets_config_subscription UNIQUE (config_id, subscription_id);


--
-- Name: campaign_vulnerabilities uk_campaign_vulnerabilities_campaign_external; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities
    ADD CONSTRAINT uk_campaign_vulnerabilities_campaign_external UNIQUE (campaign_id, external_id);


--
-- Name: ci_aliases uk_ci_aliases_tenant_alias_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ci_aliases
    ADD CONSTRAINT uk_ci_aliases_tenant_alias_source UNIQUE (tenant_id, normalized_alias_name, source_system);


--
-- Name: cis uk_cis_asset_id; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cis
    ADD CONSTRAINT uk_cis_asset_id UNIQUE (asset_id);


--
-- Name: cis uk_cis_tenant_sys_id; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cis
    ADD CONSTRAINT uk_cis_tenant_sys_id UNIQUE (tenant_id, sys_id);


--
-- Name: component_vulnerability_states uk_component_vuln_state_tenant_component_vulnerability; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states
    ADD CONSTRAINT uk_component_vuln_state_tenant_component_vulnerability UNIQUE (tenant_id, component_id, vulnerability_id);


--
-- Name: demo_invites uk_demo_invites_token; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_invites
    ADD CONSTRAINT uk_demo_invites_token UNIQUE (token);


--
-- Name: discovery_models uk_discovery_models_tenant_primary_key; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.discovery_models
    ADD CONSTRAINT uk_discovery_models_tenant_primary_key UNIQUE (tenant_id, primary_key);


--
-- Name: inventory_component_cpe_map uk_inventory_component_cpe; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map
    ADD CONSTRAINT uk_inventory_component_cpe UNIQUE (tenant_id, component_id, cpe_id);


--
-- Name: org_cve_records uk_org_cve_record_tenant_vulnerability; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_records
    ADD CONSTRAINT uk_org_cve_record_tenant_vulnerability UNIQUE (tenant_id, vulnerability_id);


--
-- Name: quality_issue_projection uk_quality_issue_projection_tenant_issue; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.quality_issue_projection
    ADD CONSTRAINT uk_quality_issue_projection_tenant_issue UNIQUE (tenant_id, issue_key);


--
-- Name: risk_policies uk_risk_policies_tenant; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.risk_policies
    ADD CONSTRAINT uk_risk_policies_tenant UNIQUE (tenant_id);


--
-- Name: sccm_cmdb_configs uk_sccm_cmdb_configs_tenant_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sccm_cmdb_configs
    ADD CONSTRAINT uk_sccm_cmdb_configs_tenant_source UNIQUE (tenant_id, source_system);


--
-- Name: service_accounts uk_service_accounts_key_id; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.service_accounts
    ADD CONSTRAINT uk_service_accounts_key_id UNIQUE (key_id);


--
-- Name: servicenow_cmdb_configs uk_servicenow_cmdb_configs_tenant_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.servicenow_cmdb_configs
    ADD CONSTRAINT uk_servicenow_cmdb_configs_tenant_source UNIQUE (tenant_id, source_system);


--
-- Name: software_instances uk_software_instances_ci_product_version_evidence; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT uk_software_instances_ci_product_version_evidence UNIQUE (ci_id, normalized_product, normalized_version, version_evidence);


--
-- Name: software_inventory_items uk_software_inventory_tenant_component; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items
    ADD CONSTRAINT uk_software_inventory_tenant_component UNIQUE (tenant_id, component_id);


--
-- Name: vulnerability_source_filter_configs uk_vulnerability_source_filter_configs_tenant_source; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.vulnerability_source_filter_configs
    ADD CONSTRAINT uk_vulnerability_source_filter_configs_tenant_source UNIQUE (tenant_id, source_system);


--
-- Name: ai_grid_exposure_observations uq_ai_grid_exposure_observation_epoch; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT uq_ai_grid_exposure_observation_epoch UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, run_id, coverage_epoch_id);


--
-- Name: investigation_runbook uq_runbook_tenant_cve; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_runbook
    ADD CONSTRAINT uq_runbook_tenant_cve UNIQUE (tenant_id, cve_external_id);


--
-- Name: vulnerability_source_filter_configs vulnerability_source_filter_configs_pkey; Type: CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.vulnerability_source_filter_configs
    ADD CONSTRAINT vulnerability_source_filter_configs_pkey PRIMARY KEY (id);


--
-- Name: idx_ai_grid_assessments_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_assessments_run ON ${tenantSchema}.ai_grid_assessments USING btree (run_id, decision);


--
-- Name: idx_ai_grid_budget_admission_cadence; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_budget_admission_cadence ON ${tenantSchema}.ai_grid_budget_admissions USING btree (provider, environment, criticality, admitted_at DESC) WHERE ((decision)::text = 'ADMITTED'::text);


--
-- Name: idx_ai_grid_budget_admissions_day; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_budget_admissions_day ON ${tenantSchema}.ai_grid_budget_admissions USING btree (admitted_at DESC, provider);


--
-- Name: idx_ai_grid_budget_alerts_open; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_budget_alerts_open ON ${tenantSchema}.ai_grid_budget_alerts USING btree (status, level);


--
-- Name: idx_ai_grid_capability_observations_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_capability_observations_run ON ${tenantSchema}.ai_grid_capability_observations USING btree (run_id, provider, capability_id);


--
-- Name: idx_ai_grid_coverage_gaps_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_coverage_gaps_epoch ON ${tenantSchema}.ai_grid_coverage_gaps USING btree (coverage_epoch_id, status, state);


--
-- Name: idx_ai_grid_current_artifacts_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_current_artifacts_epoch ON ${tenantSchema}.ai_grid_current_coverage_artifacts USING btree (epoch_id, provider, resource_family);


--
-- Name: idx_ai_grid_current_candidates_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_current_candidates_epoch ON ${tenantSchema}.ai_grid_current_expected_candidates USING btree (epoch_id, provider, resource_family, policy_id);


--
-- Name: idx_ai_grid_evidence_holds_body; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_evidence_holds_body ON ${tenantSchema}.ai_grid_evidence_holds USING btree (snapshot_body_id, released_at, expires_at);


--
-- Name: idx_ai_grid_exposure_current; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_exposure_current ON ${tenantSchema}.ai_grid_exposure_paths USING btree (status, state, last_observed_at DESC);


--
-- Name: idx_ai_grid_exposure_execution_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_exposure_execution_run ON ${tenantSchema}.ai_grid_exposure_executions USING btree (trigger_run_id, created_at DESC);


--
-- Name: idx_ai_grid_exposure_observation_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_exposure_observation_epoch ON ${tenantSchema}.ai_grid_exposure_observations USING btree (coverage_epoch_id, exposure_path_id);


--
-- Name: idx_ai_grid_exposure_observation_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_exposure_observation_run ON ${tenantSchema}.ai_grid_exposure_observations USING btree (run_id, state);


--
-- Name: idx_ai_grid_facts_current; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_facts_current ON ${tenantSchema}.ai_grid_facts USING btree (artifact_id, fact_key, observed_at DESC);


--
-- Name: idx_ai_grid_gaps_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_gaps_status ON ${tenantSchema}.ai_grid_coverage_gaps USING btree (status, last_observed_at DESC);


--
-- Name: idx_ai_grid_host_context_current; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_host_context_current ON ${tenantSchema}.ai_grid_host_context_facts USING btree (artifact_id, fact_key, observed_at DESC);


--
-- Name: idx_ai_grid_host_context_producer; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_host_context_producer ON ${tenantSchema}.ai_grid_host_context_facts USING btree (producer_id, confidence_method_version, observed_at DESC);


--
-- Name: idx_ai_grid_lineage_system; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_lineage_system ON ${tenantSchema}.ai_grid_system_lineage_participants USING btree (system_id, participant_role);


--
-- Name: idx_ai_grid_outbox_work; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_outbox_work ON ${tenantSchema}.ai_grid_outbox USING btree (status, available_at, created_at);


--
-- Name: idx_ai_grid_owner_history_artifact; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_owner_history_artifact ON ${tenantSchema}.ai_grid_owner_history USING btree (artifact_id, changed_at DESC);


--
-- Name: idx_ai_grid_policy_overrides_artifact; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_policy_overrides_artifact ON ${tenantSchema}.ai_grid_policy_artifact_overrides USING btree (artifact_id);


--
-- Name: idx_ai_grid_policy_overrides_policy; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_policy_overrides_policy ON ${tenantSchema}.ai_grid_policy_artifact_overrides USING btree (policy_id);


--
-- Name: idx_ai_grid_policy_readiness_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_policy_readiness_epoch ON ${tenantSchema}.ai_grid_policy_readiness USING btree (coverage_epoch_id, selection, readiness);


--
-- Name: idx_ai_grid_policy_readiness_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_policy_readiness_run ON ${tenantSchema}.ai_grid_policy_readiness USING btree (run_id, selection, readiness);


--
-- Name: idx_ai_grid_relationship_snapshots_source; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_relationship_snapshots_source ON ${tenantSchema}.ai_grid_relationship_snapshots USING btree (run_id, source_artifact_id, relationship_type);


--
-- Name: idx_ai_grid_retention_purge_audit_time; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_retention_purge_audit_time ON ${tenantSchema}.ai_grid_retention_purge_audit USING btree (purged_at DESC);


--
-- Name: idx_ai_grid_run_metrics_updated; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_run_metrics_updated ON ${tenantSchema}.ai_grid_run_metrics USING btree (updated_at DESC);


--
-- Name: idx_ai_grid_run_scope_metrics_run; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_run_scope_metrics_run ON ${tenantSchema}.ai_grid_run_scope_metrics USING btree (run_id);


--
-- Name: idx_ai_grid_setup_actions_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_setup_actions_epoch ON ${tenantSchema}.ai_grid_setup_actions USING btree (coverage_epoch_id, status, priority);


--
-- Name: idx_ai_grid_setup_actions_open; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_setup_actions_open ON ${tenantSchema}.ai_grid_setup_actions USING btree (run_id, status, priority, category);


--
-- Name: idx_ai_grid_snapshot_manifest_connector; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_snapshot_manifest_connector ON ${tenantSchema}.ai_grid_snapshot_manifests USING btree (connector_config_id, created_at, run_id);


--
-- Name: idx_ai_grid_snapshot_retention; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_snapshot_retention ON ${tenantSchema}.ai_grid_snapshot_bodies USING btree (retention_state, retain_until);


--
-- Name: idx_ai_grid_system_revision_epoch; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_grid_system_revision_epoch ON ${tenantSchema}.ai_grid_system_revisions USING btree (coverage_epoch_id, system_id);


--
-- Name: idx_ai_security_artifacts_scope; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_artifacts_scope ON ${tenantSchema}.ai_security_artifacts USING btree (account_id, region, native_kind);


--
-- Name: idx_ai_security_artifacts_type_active; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_artifacts_type_active ON ${tenantSchema}.ai_security_artifacts USING btree (artifact_type, active, last_observed_at DESC);


--
-- Name: idx_ai_security_azure_credentials_expiry; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_azure_credentials_expiry ON ${tenantSchema}.ai_security_azure_credential_profiles USING btree (status, active_secret_expires_at);


--
-- Name: idx_ai_security_connector_provider_target; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_connector_provider_target ON ${tenantSchema}.ai_security_connector_configs USING btree (provider, source_target_id);


--
-- Name: idx_ai_security_relationships_source; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_relationships_source ON ${tenantSchema}.ai_security_relationships USING btree (source_artifact_id, active);


--
-- Name: idx_ai_security_relationships_target; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_relationships_target ON ${tenantSchema}.ai_security_relationships USING btree (target_artifact_id, active);


--
-- Name: idx_ai_security_scopes_run_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ai_security_scopes_run_status ON ${tenantSchema}.ai_security_snapshot_scopes USING btree (run_id, status);


--
-- Name: idx_assets_tenant_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_assets_tenant_id ON ${tenantSchema}.assets USING btree (tenant_id);


--
-- Name: idx_aws_discovery_configs_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_aws_discovery_configs_enabled ON ${tenantSchema}.aws_discovery_configs USING btree (enabled, auto_sync_enabled);


--
-- Name: idx_aws_discovery_configs_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_aws_discovery_configs_tenant ON ${tenantSchema}.aws_discovery_configs USING btree (tenant_id);


--
-- Name: idx_aws_discovery_targets_config; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_aws_discovery_targets_config ON ${tenantSchema}.aws_discovery_targets USING btree (config_id);


--
-- Name: idx_aws_discovery_targets_tenant_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_aws_discovery_targets_tenant_enabled ON ${tenantSchema}.aws_discovery_targets USING btree (tenant_id, enabled);


--
-- Name: idx_azure_discovery_configs_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_azure_discovery_configs_enabled ON ${tenantSchema}.azure_discovery_configs USING btree (enabled, auto_sync_enabled);


--
-- Name: idx_azure_discovery_configs_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_azure_discovery_configs_tenant ON ${tenantSchema}.azure_discovery_configs USING btree (tenant_id);


--
-- Name: idx_azure_discovery_targets_config; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_azure_discovery_targets_config ON ${tenantSchema}.azure_discovery_targets USING btree (config_id);


--
-- Name: idx_azure_discovery_targets_tenant_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_azure_discovery_targets_tenant_enabled ON ${tenantSchema}.azure_discovery_targets USING btree (tenant_id, enabled);


--
-- Name: idx_bom_comp_active; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_comp_active ON ${tenantSchema}.bom_components USING btree (bom_id, is_active);


--
-- Name: idx_bom_comp_bom_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_comp_bom_id ON ${tenantSchema}.bom_components USING btree (bom_id);


--
-- Name: idx_bom_comp_cpe; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_comp_cpe ON ${tenantSchema}.bom_components USING btree (cpe) WHERE (cpe IS NOT NULL);


--
-- Name: idx_bom_comp_purl; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_comp_purl ON ${tenantSchema}.bom_components USING btree (purl) WHERE (purl IS NOT NULL);


--
-- Name: idx_bom_comp_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_comp_tenant ON ${tenantSchema}.bom_components USING btree (tenant_id);


--
-- Name: idx_bom_evidence_bom; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_evidence_bom ON ${tenantSchema}.bom_component_evidence USING btree (bom_id);


--
-- Name: idx_bom_evidence_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_evidence_component ON ${tenantSchema}.bom_component_evidence USING btree (bom_component_id, evidence_type);


--
-- Name: idx_bom_ir_asset; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_asset ON ${tenantSchema}.bom_ingestion_records USING btree (asset_id);


--
-- Name: idx_bom_ir_ingested_at; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_ingested_at ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id, ingested_at DESC);


--
-- Name: idx_bom_ir_source_system; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_source_system ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id, source_system);


--
-- Name: idx_bom_ir_source_type; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_source_type ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id, source_type, status);


--
-- Name: idx_bom_ir_spec_family; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_spec_family ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id, spec_family, format_version);


--
-- Name: idx_bom_ir_status_type; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_status_type ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id, bom_type, status);


--
-- Name: idx_bom_ir_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_ir_tenant ON ${tenantSchema}.bom_ingestion_records USING btree (tenant_id);


--
-- Name: idx_bom_vuln_link_bom; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_vuln_link_bom ON ${tenantSchema}.bom_component_vulnerability_links USING btree (bom_id);


--
-- Name: idx_bom_vuln_link_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_vuln_link_component ON ${tenantSchema}.bom_component_vulnerability_links USING btree (bom_component_id, vulnerability_key);


--
-- Name: idx_bom_vuln_link_source; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_vuln_link_source ON ${tenantSchema}.bom_component_vulnerability_links USING btree (tenant_id, vulnerability_source, relation_type);


--
-- Name: idx_bom_workflow_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_workflow_component ON ${tenantSchema}.bom_component_workflows USING btree (bom_component_id, workflow_status);


--
-- Name: idx_bom_workflow_link; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_bom_workflow_link ON ${tenantSchema}.bom_component_workflows USING btree (vulnerability_link_id);


--
-- Name: idx_campaign_activities_campaign_created; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_activities_campaign_created ON ${tenantSchema}.campaign_activities USING btree (campaign_id, created_at DESC);


--
-- Name: idx_campaign_delivery_attempts_campaign_created; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_delivery_attempts_campaign_created ON ${tenantSchema}.campaign_delivery_attempts USING btree (campaign_id, created_at DESC);


--
-- Name: idx_campaign_exceptions_campaign_requested; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_exceptions_campaign_requested ON ${tenantSchema}.campaign_exceptions USING btree (campaign_id, requested_at DESC);


--
-- Name: idx_campaign_notes_campaign_created; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_notes_campaign_created ON ${tenantSchema}.campaign_notes USING btree (campaign_id, created_at DESC);


--
-- Name: idx_campaign_notify_groups_campaign; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_notify_groups_campaign ON ${tenantSchema}.campaign_notify_groups USING btree (campaign_id);


--
-- Name: idx_campaign_vulnerabilities_campaign; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_vulnerabilities_campaign ON ${tenantSchema}.campaign_vulnerabilities USING btree (campaign_id, external_id);


--
-- Name: idx_campaign_watchlist_entries_campaign; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaign_watchlist_entries_campaign ON ${tenantSchema}.campaign_watchlist_entries USING btree (campaign_id);


--
-- Name: idx_campaigns_tenant_status_updated; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_campaigns_tenant_status_updated ON ${tenantSchema}.campaigns USING btree (tenant_id, status, updated_at DESC);


--
-- Name: idx_cbom_components_asset_type; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_components_asset_type ON ${tenantSchema}.cbom_components USING btree (tenant_id, asset_type);


--
-- Name: idx_cbom_components_bom_ref; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_components_bom_ref ON ${tenantSchema}.cbom_components USING btree (tenant_id, asset_id, bom_ref) WHERE (bom_ref IS NOT NULL);


--
-- Name: idx_cbom_components_source_bom; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_components_source_bom ON ${tenantSchema}.cbom_components USING btree (source_bom_id);


--
-- Name: idx_cbom_components_tenant_asset; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_components_tenant_asset ON ${tenantSchema}.cbom_components USING btree (tenant_id, asset_id);


--
-- Name: idx_cbom_posture_summary_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_posture_summary_tenant ON ${tenantSchema}.cbom_posture_summary USING btree (tenant_id);


--
-- Name: idx_cbom_risk_findings_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_risk_findings_component ON ${tenantSchema}.cbom_risk_findings USING btree (cbom_component_id);


--
-- Name: idx_cbom_risk_findings_tenant_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cbom_risk_findings_tenant_status ON ${tenantSchema}.cbom_risk_findings USING btree (tenant_id, status, severity);


--
-- Name: idx_ci_aliases_ci; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ci_aliases_ci ON ${tenantSchema}.ci_aliases USING btree (ci_id);


--
-- Name: idx_ci_aliases_tenant_alias; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ci_aliases_tenant_alias ON ${tenantSchema}.ci_aliases USING btree (tenant_id, normalized_alias_name);


--
-- Name: idx_cis_tenant_display; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cis_tenant_display ON ${tenantSchema}.cis USING btree (tenant_id, display_name);


--
-- Name: idx_cis_tenant_env; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cis_tenant_env ON ${tenantSchema}.cis USING btree (tenant_id, environment);


--
-- Name: idx_cluster_link_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_cluster_link_tenant ON ${tenantSchema}.software_identity_cluster_link USING btree (tenant_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_comp_vuln_state_tenant_applicability; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_applicability ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, applicability_state);


--
-- Name: idx_comp_vuln_state_tenant_component_vuln; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_component_vuln ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, component_id, vulnerability_id);


--
-- Name: idx_comp_vuln_state_tenant_eligible; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_eligible ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, eligible_for_finding);


--
-- Name: idx_comp_vuln_state_tenant_impact; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_impact ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, impact_state);


--
-- Name: idx_comp_vuln_state_tenant_impact_updated; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_impact_updated ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, impact_state, updated_at);


--
-- Name: idx_comp_vuln_state_tenant_vuln_impact; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_vuln_impact ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, vulnerability_id, impact_state);


--
-- Name: idx_comp_vuln_state_tenant_vulnerability_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_comp_vuln_state_tenant_vulnerability_component ON ${tenantSchema}.component_vulnerability_states USING btree (tenant_id, vulnerability_id, component_id);


--
-- Name: idx_dashboard_noise_reduction_projection_last_computed; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_dashboard_noise_reduction_projection_last_computed ON ${tenantSchema}.dashboard_noise_reduction_projection USING btree (last_computed_at DESC);


--
-- Name: idx_discovery_models_product_hash; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_discovery_models_product_hash ON ${tenantSchema}.discovery_models USING btree (product_hash);


--
-- Name: idx_discovery_models_version_hash; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_discovery_models_version_hash ON ${tenantSchema}.discovery_models USING btree (version_hash);


--
-- Name: idx_fdq_dedupe_pending; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX idx_fdq_dedupe_pending ON ${tenantSchema}.finding_delta_queue USING btree (dedupe_key) WHERE ((status)::text = 'PENDING'::text);


--
-- Name: idx_fdq_pending_visible; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_fdq_pending_visible ON ${tenantSchema}.finding_delta_queue USING btree (status, visible_after, id) WHERE ((status)::text = 'PENDING'::text);


--
-- Name: idx_finding_comments_finding_created; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_comments_finding_created ON ${tenantSchema}.finding_comments USING btree (finding_id, created_at);


--
-- Name: idx_finding_events_finding_created; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_events_finding_created ON ${tenantSchema}.finding_events USING btree (finding_id, created_at);


--
-- Name: idx_finding_list_projection_assigned_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_assigned_status ON ${tenantSchema}.finding_list_projection USING btree (assigned_to, status);


--
-- Name: idx_finding_list_projection_incident_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_incident_status ON ${tenantSchema}.finding_list_projection USING btree (incident_id, status);


--
-- Name: idx_finding_list_projection_owner_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_owner_status ON ${tenantSchema}.finding_list_projection USING btree (owner_group, status);


--
-- Name: idx_finding_list_projection_patch_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_patch_status ON ${tenantSchema}.finding_list_projection USING btree (patch_available, status);


--
-- Name: idx_finding_list_projection_severity_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_severity_status ON ${tenantSchema}.finding_list_projection USING btree (severity, status);


--
-- Name: idx_finding_list_projection_status_due; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_status_due ON ${tenantSchema}.finding_list_projection USING btree (status, due_at);


--
-- Name: idx_finding_list_projection_support_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_support_status ON ${tenantSchema}.finding_list_projection USING btree (support_group, status);


--
-- Name: idx_finding_list_projection_suppressed_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_suppressed_status ON ${tenantSchema}.finding_list_projection USING btree (suppressed_until, status);


--
-- Name: idx_finding_list_projection_updated_tiebreak; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_list_projection_updated_tiebreak ON ${tenantSchema}.finding_list_projection USING btree (updated_at, finding_id);


--
-- Name: idx_finding_reviews_finding; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_reviews_finding ON ${tenantSchema}.finding_reviews USING btree (finding_id, reviewed_at DESC);


--
-- Name: idx_finding_subjects_subject; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_finding_subjects_subject ON ${tenantSchema}.finding_subjects USING btree (subject_type, subject_id);


--
-- Name: idx_findings_asset_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_asset_id ON ${tenantSchema}.findings USING btree (asset_id);


--
-- Name: idx_findings_auto_close_eligible; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_auto_close_eligible ON ${tenantSchema}.findings USING btree (tenant_id, status, auto_close_eligible_at);


--
-- Name: idx_findings_tenant_component_vuln; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_tenant_component_vuln ON ${tenantSchema}.findings USING btree (tenant_id, component_id, vulnerability_id);


--
-- Name: idx_findings_tenant_status_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_tenant_status_component ON ${tenantSchema}.findings USING btree (tenant_id, status, component_id);


--
-- Name: idx_findings_tenant_status_updated; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_tenant_status_updated ON ${tenantSchema}.findings USING btree (tenant_id, status, updated_at);


--
-- Name: idx_findings_vex_freshness; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_vex_freshness ON ${tenantSchema}.findings USING btree (vex_freshness);


--
-- Name: idx_findings_vex_provider; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_vex_provider ON ${tenantSchema}.findings USING btree (vex_provider);


--
-- Name: idx_findings_vex_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_vex_status ON ${tenantSchema}.findings USING btree (vex_status);


--
-- Name: idx_findings_vulnerability_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_vulnerability_id ON ${tenantSchema}.findings USING btree (vulnerability_id);


--
-- Name: idx_findings_vulnerability_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_findings_vulnerability_status ON ${tenantSchema}.findings USING btree (vulnerability_id, status);


--
-- Name: idx_fix_records_patchable_upper_cve; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_fix_records_patchable_upper_cve ON ${tenantSchema}.fix_records USING btree (upper((cve_id)::text)) WHERE (upper((fix_type)::text) <> 'NO_FIX'::text);


--
-- Name: idx_fix_records_tenant_cve; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_fix_records_tenant_cve ON ${tenantSchema}.fix_records USING btree (tenant_id, cve_id);


--
-- Name: idx_github_sbom_sources_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_github_sbom_sources_enabled ON ${tenantSchema}.github_sbom_sources USING btree (enabled, last_run_at);


--
-- Name: idx_github_sbom_sources_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_github_sbom_sources_tenant ON ${tenantSchema}.github_sbom_sources USING btree (tenant_id, enabled, created_at);


--
-- Name: idx_iccm_tenant_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_iccm_tenant_component ON ${tenantSchema}.inventory_component_cpe_map USING btree (tenant_id, component_id);


--
-- Name: idx_iccm_tenant_cpe; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_iccm_tenant_cpe ON ${tenantSchema}.inventory_component_cpe_map USING btree (tenant_id, cpe_id);


--
-- Name: idx_ingestion_jobs_asset_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ingestion_jobs_asset_status ON ${tenantSchema}.ingestion_jobs USING btree (asset_identifier, status);


--
-- Name: idx_ingestion_jobs_requested_desc; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ingestion_jobs_requested_desc ON ${tenantSchema}.ingestion_jobs USING btree (requested_at DESC, id DESC);


--
-- Name: idx_ingestion_jobs_status_visible; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_ingestion_jobs_status_visible ON ${tenantSchema}.ingestion_jobs USING btree (status, visible_at, id);


--
-- Name: idx_inventory_component_digest; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_component_digest ON ${tenantSchema}.inventory_components USING btree (component_digest);


--
-- Name: idx_inventory_components_manual_identity; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_components_manual_identity ON ${tenantSchema}.inventory_components USING btree (manual_identity_id) WHERE (manual_identity_id IS NOT NULL);


--
-- Name: idx_inventory_coord_key_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_coord_key_tenant ON ${tenantSchema}.inventory_components USING btree (tenant_id, coord_key);


--
-- Name: idx_inventory_norm_purl_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_norm_purl_tenant ON ${tenantSchema}.inventory_components USING btree (tenant_id, normalized_purl);


--
-- Name: idx_inventory_sbom_upload; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_sbom_upload ON ${tenantSchema}.inventory_components USING btree (sbom_upload_id);


--
-- Name: idx_inventory_software_identity; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_software_identity ON ${tenantSchema}.inventory_components USING btree (software_identity_id);


--
-- Name: idx_inventory_tenant_asset; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_tenant_asset ON ${tenantSchema}.inventory_components USING btree (tenant_id, asset_id);


--
-- Name: idx_inventory_tenant_software_identity; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_inventory_tenant_software_identity ON ${tenantSchema}.inventory_components USING btree (tenant_id, software_identity_id);


--
-- Name: idx_org_cve_record_tenant_applicability; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_applicability ON ${tenantSchema}.org_cve_records USING btree (tenant_id, applicability_state);


--
-- Name: idx_org_cve_record_tenant_created_at; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_created_at ON ${tenantSchema}.org_cve_records USING btree (tenant_id, created_at DESC);


--
-- Name: idx_org_cve_record_tenant_exposure_browse; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_exposure_browse ON ${tenantSchema}.org_cve_records USING btree (tenant_id, applicability_state, matched_asset_count, impacted, in_kev, epss_score DESC, cvss_score DESC, external_id);


--
-- Name: idx_org_cve_record_tenant_external_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_external_id ON ${tenantSchema}.org_cve_records USING btree (tenant_id, external_id);


--
-- Name: idx_org_cve_record_tenant_impact_state; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_impact_state ON ${tenantSchema}.org_cve_records USING btree (tenant_id, impact_state);


--
-- Name: idx_org_cve_record_tenant_impacted; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_impacted ON ${tenantSchema}.org_cve_records USING btree (tenant_id, impacted);


--
-- Name: idx_org_cve_record_tenant_rank; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_rank ON ${tenantSchema}.org_cve_records USING btree (tenant_id, impacted, applicability_state, cvss_score, external_id);


--
-- Name: idx_org_cve_record_tenant_suppressed_until; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_suppressed_until ON ${tenantSchema}.org_cve_records USING btree (tenant_id, suppressed_until);


--
-- Name: idx_org_cve_record_tenant_upper_severity; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_upper_severity ON ${tenantSchema}.org_cve_records USING btree (tenant_id, upper((COALESCE(severity, 'UNKNOWN'::character varying))::text));


--
-- Name: idx_org_cve_record_tenant_vulnerability; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_org_cve_record_tenant_vulnerability ON ${tenantSchema}.org_cve_records USING btree (tenant_id, vulnerability_id);


--
-- Name: idx_quality_issue_projection_domain; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_quality_issue_projection_domain ON ${tenantSchema}.quality_issue_projection USING btree (tenant_id, domain, severity, last_seen_at DESC);


--
-- Name: idx_quality_issue_projection_filters; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_quality_issue_projection_filters ON ${tenantSchema}.quality_issue_projection USING btree (tenant_id, affects_active_findings, asset_type, source_system, ecosystem);


--
-- Name: idx_quality_issue_projection_refs; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_quality_issue_projection_refs ON ${tenantSchema}.quality_issue_projection USING btree (tenant_id, vulnerability_id, software_identity_id, component_id, asset_id);


--
-- Name: idx_runbook_cve_external_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_runbook_cve_external_id ON ${tenantSchema}.investigation_runbook USING btree (cve_external_id);


--
-- Name: idx_runbook_tenant_id; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_runbook_tenant_id ON ${tenantSchema}.investigation_runbook USING btree (tenant_id);


--
-- Name: idx_sbom_upload_asset_uploaded; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_sbom_upload_asset_uploaded ON ${tenantSchema}.sbom_uploads USING btree (asset_id, uploaded_at);


--
-- Name: idx_sbom_upload_tenant_uploaded; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_sbom_upload_tenant_uploaded ON ${tenantSchema}.sbom_uploads USING btree (tenant_id, uploaded_at);


--
-- Name: idx_sccm_cmdb_configs_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_sccm_cmdb_configs_enabled ON ${tenantSchema}.sccm_cmdb_configs USING btree (enabled, auto_sync_enabled);


--
-- Name: idx_sccm_cmdb_configs_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_sccm_cmdb_configs_tenant ON ${tenantSchema}.sccm_cmdb_configs USING btree (tenant_id);


--
-- Name: idx_servicenow_cmdb_configs_enabled; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_servicenow_cmdb_configs_enabled ON ${tenantSchema}.servicenow_cmdb_configs USING btree (enabled, auto_sync_enabled);


--
-- Name: idx_servicenow_cmdb_configs_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_servicenow_cmdb_configs_tenant ON ${tenantSchema}.servicenow_cmdb_configs USING btree (tenant_id);


--
-- Name: idx_software_identity_summary_normalized_key; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_identity_summary_normalized_key ON ${tenantSchema}.software_identity_summary USING btree (normalized_key);


--
-- Name: idx_software_identity_summary_tenant_component_count; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_identity_summary_tenant_component_count ON ${tenantSchema}.software_identity_summary USING btree (tenant_id, component_count DESC, display_name);


--
-- Name: idx_software_identity_summary_tenant_lifecycle; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_identity_summary_tenant_lifecycle ON ${tenantSchema}.software_identity_summary USING btree (tenant_id, eol_component_count DESC, near_eol_component_count DESC, unknown_eol_component_count DESC);


--
-- Name: idx_software_identity_summary_tenant_mapping; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_identity_summary_tenant_mapping ON ${tenantSchema}.software_identity_summary USING btree (tenant_id, needs_eol_mapping, mapping_confirmed);


--
-- Name: idx_software_instances_ci; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_instances_ci ON ${tenantSchema}.software_instances USING btree (ci_id);


--
-- Name: idx_software_instances_discovery_model; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_instances_discovery_model ON ${tenantSchema}.software_instances USING btree (discovery_model_id);


--
-- Name: idx_software_instances_identity; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_instances_identity ON ${tenantSchema}.software_instances USING btree (software_identity_id);


--
-- Name: idx_software_inventory_tenant_component; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_inventory_tenant_component ON ${tenantSchema}.software_inventory_items USING btree (tenant_id, component_id);


--
-- Name: idx_software_inventory_tenant_pkg; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_inventory_tenant_pkg ON ${tenantSchema}.software_inventory_items USING btree (tenant_id, ecosystem, package_name, version);


--
-- Name: idx_software_inventory_tenant_status; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_software_inventory_tenant_status ON ${tenantSchema}.software_inventory_items USING btree (tenant_id, component_status);


--
-- Name: idx_vulnerability_source_filter_configs_tenant; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE INDEX idx_vulnerability_source_filter_configs_tenant ON ${tenantSchema}.vulnerability_source_filter_configs USING btree (tenant_id);


--
-- Name: uk_ai_grid_budget_alert_open_metric; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uk_ai_grid_budget_alert_open_metric ON ${tenantSchema}.ai_grid_budget_alerts USING btree (tenant_id, metric) WHERE ((status)::text = ANY (ARRAY[('OPEN'::character varying)::text, ('ACKNOWLEDGED'::character varying)::text]));


--
-- Name: uk_demo_requests_active_email; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uk_demo_requests_active_email ON ${tenantSchema}.demo_requests USING btree (lower((email)::text)) WHERE ((status)::text = ANY ((ARRAY['PENDING'::character varying, 'SENT'::character varying, 'ERROR'::character varying])::text[]));


--
-- Name: uk_findings_component_vulnerability; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uk_findings_component_vulnerability ON ${tenantSchema}.findings USING btree (component_id, vulnerability_id) WHERE ((finding_kind)::text = 'VULNERABILITY'::text);


--
-- Name: uk_findings_tenant_fingerprint; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uk_findings_tenant_fingerprint ON ${tenantSchema}.findings USING btree (tenant_id, fingerprint) WHERE (fingerprint IS NOT NULL);


--
-- Name: uk_ingestion_jobs_dedupe_active; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uk_ingestion_jobs_dedupe_active ON ${tenantSchema}.ingestion_jobs USING btree (dedupe_key) WHERE ((status)::text = ANY ((ARRAY['QUEUED'::character varying, 'RUNNING'::character varying])::text[]));


--
-- Name: uq_cluster_link_active; Type: INDEX; Schema: ${tenantSchema}; Owner: -
--

CREATE UNIQUE INDEX uq_cluster_link_active ON ${tenantSchema}.software_identity_cluster_link USING btree (tenant_id, source_type, source_key) WHERE (revoked_at IS NULL);


--
-- Name: ai_grid_artifact_classifications ai_grid_artifact_classifications_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_artifact_classifications
    ADD CONSTRAINT ai_grid_artifact_classifications_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_artifact_classifications ai_grid_artifact_classifications_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_artifact_classifications
    ADD CONSTRAINT ai_grid_artifact_classifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_assessments ai_grid_assessments_snapshot_manifest_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_assessments
    ADD CONSTRAINT ai_grid_assessments_snapshot_manifest_id_fkey FOREIGN KEY (snapshot_manifest_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_manifests(id);


--
-- Name: ai_grid_assessments ai_grid_assessments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_assessments
    ADD CONSTRAINT ai_grid_assessments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_budget_admissions ai_grid_budget_admissions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_admissions
    ADD CONSTRAINT ai_grid_budget_admissions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_budget_alerts ai_grid_budget_alerts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_alerts
    ADD CONSTRAINT ai_grid_budget_alerts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_budget_config ai_grid_budget_config_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_budget_config
    ADD CONSTRAINT ai_grid_budget_config_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_capability_observations ai_grid_capability_observations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_capability_observations
    ADD CONSTRAINT ai_grid_capability_observations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_coverage_gaps ai_grid_coverage_gaps_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_coverage_gaps
    ADD CONSTRAINT ai_grid_coverage_gaps_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_coverage_gaps ai_grid_coverage_gaps_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_coverage_gaps
    ADD CONSTRAINT ai_grid_coverage_gaps_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_current_coverage_artifacts ai_grid_current_coverage_artifacts_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_artifacts
    ADD CONSTRAINT ai_grid_current_coverage_artifacts_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_current_coverage_artifacts ai_grid_current_coverage_artifacts_snapshot_manifest_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_artifacts
    ADD CONSTRAINT ai_grid_current_coverage_artifacts_snapshot_manifest_id_fkey FOREIGN KEY (snapshot_manifest_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_manifests(id) ON DELETE CASCADE;


--
-- Name: ai_grid_current_coverage_artifacts ai_grid_current_coverage_artifacts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_artifacts
    ADD CONSTRAINT ai_grid_current_coverage_artifacts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_current_coverage_state ai_grid_current_coverage_state_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_coverage_state
    ADD CONSTRAINT ai_grid_current_coverage_state_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_current_expected_candidates ai_grid_current_expected_candidates_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_expected_candidates
    ADD CONSTRAINT ai_grid_current_expected_candidates_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_current_expected_candidates ai_grid_current_expected_candidates_snapshot_manifest_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_expected_candidates
    ADD CONSTRAINT ai_grid_current_expected_candidates_snapshot_manifest_id_fkey FOREIGN KEY (snapshot_manifest_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_manifests(id) ON DELETE CASCADE;


--
-- Name: ai_grid_current_expected_candidates ai_grid_current_expected_candidates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_current_expected_candidates
    ADD CONSTRAINT ai_grid_current_expected_candidates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_evidence_holds ai_grid_evidence_holds_snapshot_body_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_evidence_holds
    ADD CONSTRAINT ai_grid_evidence_holds_snapshot_body_id_fkey FOREIGN KEY (snapshot_body_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_bodies(id) ON DELETE CASCADE;


--
-- Name: ai_grid_evidence_holds ai_grid_evidence_holds_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_evidence_holds
    ADD CONSTRAINT ai_grid_evidence_holds_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_exposure_path_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_exposure_path_id_fkey FOREIGN KEY (exposure_path_id) REFERENCES ${tenantSchema}.ai_grid_exposure_paths(id) ON DELETE CASCADE;


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id) ON DELETE CASCADE;


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_system_revision_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_system_revision_id_fkey FOREIGN KEY (system_revision_id) REFERENCES ${tenantSchema}.ai_grid_system_revisions(id) ON DELETE SET NULL;


--
-- Name: ai_grid_exposure_associations ai_grid_exposure_associations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_associations
    ADD CONSTRAINT ai_grid_exposure_associations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_exposure_dispositions ai_grid_exposure_dispositions_exposure_path_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_dispositions
    ADD CONSTRAINT ai_grid_exposure_dispositions_exposure_path_id_fkey FOREIGN KEY (exposure_path_id) REFERENCES ${tenantSchema}.ai_grid_exposure_paths(id) ON DELETE CASCADE;


--
-- Name: ai_grid_exposure_dispositions ai_grid_exposure_dispositions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_dispositions
    ADD CONSTRAINT ai_grid_exposure_dispositions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_exposure_executions ai_grid_exposure_executions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_executions
    ADD CONSTRAINT ai_grid_exposure_executions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_entry_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_entry_artifact_id_fkey FOREIGN KEY (entry_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id);


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_exposure_path_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_exposure_path_id_fkey FOREIGN KEY (exposure_path_id) REFERENCES ${tenantSchema}.ai_grid_exposure_paths(id) ON DELETE CASCADE;


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id);


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_system_revision_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_system_revision_id_fkey FOREIGN KEY (system_revision_id) REFERENCES ${tenantSchema}.ai_grid_system_revisions(id);


--
-- Name: ai_grid_exposure_observations ai_grid_exposure_observations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_observations
    ADD CONSTRAINT ai_grid_exposure_observations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_exposure_paths ai_grid_exposure_paths_finding_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths
    ADD CONSTRAINT ai_grid_exposure_paths_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES ${tenantSchema}.findings(id) ON DELETE SET NULL;


--
-- Name: ai_grid_exposure_paths ai_grid_exposure_paths_root_cause_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths
    ADD CONSTRAINT ai_grid_exposure_paths_root_cause_artifact_id_fkey FOREIGN KEY (root_cause_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id);


--
-- Name: ai_grid_exposure_paths ai_grid_exposure_paths_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_exposure_paths
    ADD CONSTRAINT ai_grid_exposure_paths_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_facts ai_grid_facts_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts
    ADD CONSTRAINT ai_grid_facts_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_facts ai_grid_facts_snapshot_manifest_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts
    ADD CONSTRAINT ai_grid_facts_snapshot_manifest_id_fkey FOREIGN KEY (snapshot_manifest_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_manifests(id) ON DELETE CASCADE;


--
-- Name: ai_grid_facts ai_grid_facts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_facts
    ADD CONSTRAINT ai_grid_facts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_host_context_facts ai_grid_host_context_facts_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_host_context_facts
    ADD CONSTRAINT ai_grid_host_context_facts_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_host_context_facts ai_grid_host_context_facts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_host_context_facts
    ADD CONSTRAINT ai_grid_host_context_facts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_outbox ai_grid_outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_outbox
    ADD CONSTRAINT ai_grid_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_owner_history ai_grid_owner_history_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_owner_history
    ADD CONSTRAINT ai_grid_owner_history_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_owner_history ai_grid_owner_history_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_owner_history
    ADD CONSTRAINT ai_grid_owner_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_artifact_overrides ai_grid_policy_artifact_overrides_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_artifact_overrides
    ADD CONSTRAINT ai_grid_policy_artifact_overrides_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_policy_artifact_overrides ai_grid_policy_artifact_overrides_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_artifact_overrides
    ADD CONSTRAINT ai_grid_policy_artifact_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_parameters ai_grid_policy_parameters_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_parameters
    ADD CONSTRAINT ai_grid_policy_parameters_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_readiness ai_grid_policy_readiness_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_readiness
    ADD CONSTRAINT ai_grid_policy_readiness_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_scopes ai_grid_policy_scopes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_scopes
    ADD CONSTRAINT ai_grid_policy_scopes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_selection_history ai_grid_policy_selection_history_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selection_history
    ADD CONSTRAINT ai_grid_policy_selection_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_selections ai_grid_policy_selections_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_policy_selections
    ADD CONSTRAINT ai_grid_policy_selections_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_relationship_snapshots ai_grid_relationship_snapshots_source_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots
    ADD CONSTRAINT ai_grid_relationship_snapshots_source_artifact_id_fkey FOREIGN KEY (source_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_relationship_snapshots ai_grid_relationship_snapshots_target_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots
    ADD CONSTRAINT ai_grid_relationship_snapshots_target_artifact_id_fkey FOREIGN KEY (target_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_relationship_snapshots ai_grid_relationship_snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_relationship_snapshots
    ADD CONSTRAINT ai_grid_relationship_snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_retention_decisions ai_grid_retention_decisions_snapshot_body_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_decisions
    ADD CONSTRAINT ai_grid_retention_decisions_snapshot_body_id_fkey FOREIGN KEY (snapshot_body_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_bodies(id) ON DELETE CASCADE;


--
-- Name: ai_grid_retention_decisions ai_grid_retention_decisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_decisions
    ADD CONSTRAINT ai_grid_retention_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_retention_policies ai_grid_retention_policies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_policies
    ADD CONSTRAINT ai_grid_retention_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_retention_purge_audit ai_grid_retention_purge_audit_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_retention_purge_audit
    ADD CONSTRAINT ai_grid_retention_purge_audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_run_metrics ai_grid_run_metrics_connector_config_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_metrics
    ADD CONSTRAINT ai_grid_run_metrics_connector_config_id_fkey FOREIGN KEY (connector_config_id) REFERENCES ${tenantSchema}.ai_security_connector_configs(id) ON DELETE SET NULL;


--
-- Name: ai_grid_run_metrics ai_grid_run_metrics_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_metrics
    ADD CONSTRAINT ai_grid_run_metrics_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_run_scope_metrics ai_grid_run_scope_metrics_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_run_scope_metrics
    ADD CONSTRAINT ai_grid_run_scope_metrics_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_scan_cadence_rules ai_grid_scan_cadence_rules_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_scan_cadence_rules
    ADD CONSTRAINT ai_grid_scan_cadence_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_setup_actions ai_grid_setup_actions_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_setup_actions
    ADD CONSTRAINT ai_grid_setup_actions_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_setup_actions ai_grid_setup_actions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_setup_actions
    ADD CONSTRAINT ai_grid_setup_actions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_snapshot_bodies ai_grid_snapshot_bodies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_bodies
    ADD CONSTRAINT ai_grid_snapshot_bodies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_body_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_body_id_fkey FOREIGN KEY (body_id) REFERENCES ${tenantSchema}.ai_grid_snapshot_bodies(id);


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_connector_config_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_connector_config_id_fkey FOREIGN KEY (connector_config_id) REFERENCES ${tenantSchema}.ai_security_connector_configs(id) ON DELETE SET NULL;


--
-- Name: ai_grid_snapshot_manifests ai_grid_snapshot_manifests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_snapshot_manifests
    ADD CONSTRAINT ai_grid_snapshot_manifests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_lineage_events ai_grid_system_lineage_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_events
    ADD CONSTRAINT ai_grid_system_lineage_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_participants_event_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_participants_event_id_fkey FOREIGN KEY (event_id) REFERENCES ${tenantSchema}.ai_grid_system_lineage_events(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_participants_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_participants_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_participants_system_revision_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_participants_system_revision_id_fkey FOREIGN KEY (system_revision_id) REFERENCES ${tenantSchema}.ai_grid_system_revisions(id) ON DELETE SET NULL;


--
-- Name: ai_grid_system_lineage_participants ai_grid_system_lineage_participants_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_lineage_participants
    ADD CONSTRAINT ai_grid_system_lineage_participants_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_membership_decisions ai_grid_system_membership_decisions_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions
    ADD CONSTRAINT ai_grid_system_membership_decisions_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_membership_decisions ai_grid_system_membership_decisions_resulting_revision_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions
    ADD CONSTRAINT ai_grid_system_membership_decisions_resulting_revision_id_fkey FOREIGN KEY (resulting_revision_id) REFERENCES ${tenantSchema}.ai_grid_system_revisions(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_membership_decisions ai_grid_system_membership_decisions_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions
    ADD CONSTRAINT ai_grid_system_membership_decisions_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_membership_decisions ai_grid_system_membership_decisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_decisions
    ADD CONSTRAINT ai_grid_system_membership_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_membership_overrides ai_grid_system_membership_overrides_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_overrides
    ADD CONSTRAINT ai_grid_system_membership_overrides_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_membership_overrides ai_grid_system_membership_overrides_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_overrides
    ADD CONSTRAINT ai_grid_system_membership_overrides_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_membership_overrides ai_grid_system_membership_overrides_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_membership_overrides
    ADD CONSTRAINT ai_grid_system_membership_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_memberships ai_grid_system_memberships_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships
    ADD CONSTRAINT ai_grid_system_memberships_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_memberships ai_grid_system_memberships_system_revision_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships
    ADD CONSTRAINT ai_grid_system_memberships_system_revision_id_fkey FOREIGN KEY (system_revision_id) REFERENCES ${tenantSchema}.ai_grid_system_revisions(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_memberships ai_grid_system_memberships_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_memberships
    ADD CONSTRAINT ai_grid_system_memberships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_system_revisions ai_grid_system_revisions_system_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_revisions
    ADD CONSTRAINT ai_grid_system_revisions_system_id_fkey FOREIGN KEY (system_id) REFERENCES ${tenantSchema}.ai_grid_systems(id) ON DELETE CASCADE;


--
-- Name: ai_grid_system_revisions ai_grid_system_revisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_system_revisions
    ADD CONSTRAINT ai_grid_system_revisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_systems ai_grid_systems_root_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_systems
    ADD CONSTRAINT ai_grid_systems_root_artifact_id_fkey FOREIGN KEY (root_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE SET NULL;


--
-- Name: ai_grid_systems ai_grid_systems_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_grid_systems
    ADD CONSTRAINT ai_grid_systems_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_artifact_sources ai_security_artifact_sources_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources
    ADD CONSTRAINT ai_security_artifact_sources_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_security_artifact_sources ai_security_artifact_sources_connector_config_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources
    ADD CONSTRAINT ai_security_artifact_sources_connector_config_id_fkey FOREIGN KEY (connector_config_id) REFERENCES ${tenantSchema}.ai_security_connector_configs(id) ON DELETE SET NULL;


--
-- Name: ai_security_artifact_sources ai_security_artifact_sources_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifact_sources
    ADD CONSTRAINT ai_security_artifact_sources_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_artifacts ai_security_artifacts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_artifacts
    ADD CONSTRAINT ai_security_artifacts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_azure_credential_profiles ai_security_azure_credential_profiles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_azure_credential_profiles
    ADD CONSTRAINT ai_security_azure_credential_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_connector_configs ai_security_connector_configs_credential_profile_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_connector_configs
    ADD CONSTRAINT ai_security_connector_configs_credential_profile_id_fkey FOREIGN KEY (credential_profile_id) REFERENCES ${tenantSchema}.ai_security_azure_credential_profiles(id) ON DELETE RESTRICT;


--
-- Name: ai_security_connector_configs ai_security_connector_configs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_connector_configs
    ADD CONSTRAINT ai_security_connector_configs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_observation_receipts ai_security_observation_receipts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_observation_receipts
    ADD CONSTRAINT ai_security_observation_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_relationships ai_security_relationships_source_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships
    ADD CONSTRAINT ai_security_relationships_source_artifact_id_fkey FOREIGN KEY (source_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_security_relationships ai_security_relationships_target_artifact_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships
    ADD CONSTRAINT ai_security_relationships_target_artifact_id_fkey FOREIGN KEY (target_artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE;


--
-- Name: ai_security_relationships ai_security_relationships_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_relationships
    ADD CONSTRAINT ai_security_relationships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_security_snapshot_scopes ai_security_snapshot_scopes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ai_security_snapshot_scopes
    ADD CONSTRAINT ai_security_snapshot_scopes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_component_evidence bom_component_evidence_bom_component_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_evidence
    ADD CONSTRAINT bom_component_evidence_bom_component_id_fkey FOREIGN KEY (bom_component_id) REFERENCES ${tenantSchema}.bom_components(id) ON DELETE CASCADE;


--
-- Name: bom_component_evidence bom_component_evidence_bom_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_evidence
    ADD CONSTRAINT bom_component_evidence_bom_id_fkey FOREIGN KEY (bom_id) REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE;


--
-- Name: bom_component_evidence bom_component_evidence_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_evidence
    ADD CONSTRAINT bom_component_evidence_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_component_vulnerability_links bom_component_vulnerability_links_bom_component_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_vulnerability_links
    ADD CONSTRAINT bom_component_vulnerability_links_bom_component_id_fkey FOREIGN KEY (bom_component_id) REFERENCES ${tenantSchema}.bom_components(id) ON DELETE CASCADE;


--
-- Name: bom_component_vulnerability_links bom_component_vulnerability_links_bom_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_vulnerability_links
    ADD CONSTRAINT bom_component_vulnerability_links_bom_id_fkey FOREIGN KEY (bom_id) REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE;


--
-- Name: bom_component_vulnerability_links bom_component_vulnerability_links_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_vulnerability_links
    ADD CONSTRAINT bom_component_vulnerability_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_component_workflows bom_component_workflows_bom_component_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_workflows
    ADD CONSTRAINT bom_component_workflows_bom_component_id_fkey FOREIGN KEY (bom_component_id) REFERENCES ${tenantSchema}.bom_components(id) ON DELETE CASCADE;


--
-- Name: bom_component_workflows bom_component_workflows_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_workflows
    ADD CONSTRAINT bom_component_workflows_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_component_workflows bom_component_workflows_vulnerability_link_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_component_workflows
    ADD CONSTRAINT bom_component_workflows_vulnerability_link_id_fkey FOREIGN KEY (vulnerability_link_id) REFERENCES ${tenantSchema}.bom_component_vulnerability_links(id) ON DELETE CASCADE;


--
-- Name: bom_components bom_components_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_components
    ADD CONSTRAINT bom_components_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_ingestion_records bom_ingestion_records_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_ingestion_records
    ADD CONSTRAINT bom_ingestion_records_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_activities campaign_activities_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_activities
    ADD CONSTRAINT campaign_activities_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_activities campaign_activities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_activities
    ADD CONSTRAINT campaign_activities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_delivery_attempts campaign_delivery_attempts_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_delivery_attempts
    ADD CONSTRAINT campaign_delivery_attempts_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_delivery_attempts campaign_delivery_attempts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_delivery_attempts
    ADD CONSTRAINT campaign_delivery_attempts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_exceptions campaign_exceptions_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_exceptions
    ADD CONSTRAINT campaign_exceptions_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_exceptions campaign_exceptions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_exceptions
    ADD CONSTRAINT campaign_exceptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_notes campaign_notes_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notes
    ADD CONSTRAINT campaign_notes_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_notes campaign_notes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notes
    ADD CONSTRAINT campaign_notes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_notify_groups campaign_notify_groups_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notify_groups
    ADD CONSTRAINT campaign_notify_groups_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_notify_groups campaign_notify_groups_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_notify_groups
    ADD CONSTRAINT campaign_notify_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_vulnerabilities campaign_vulnerabilities_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities
    ADD CONSTRAINT campaign_vulnerabilities_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_vulnerabilities campaign_vulnerabilities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities
    ADD CONSTRAINT campaign_vulnerabilities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaign_vulnerabilities campaign_vulnerabilities_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_vulnerabilities
    ADD CONSTRAINT campaign_vulnerabilities_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: campaign_watchlist_entries campaign_watchlist_entries_campaign_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_watchlist_entries
    ADD CONSTRAINT campaign_watchlist_entries_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_watchlist_entries campaign_watchlist_entries_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaign_watchlist_entries
    ADD CONSTRAINT campaign_watchlist_entries_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: campaigns campaigns_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.campaigns
    ADD CONSTRAINT campaigns_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: cbom_components cbom_components_asset_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_components
    ADD CONSTRAINT cbom_components_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: cbom_components cbom_components_source_bom_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_components
    ADD CONSTRAINT cbom_components_source_bom_id_fkey FOREIGN KEY (source_bom_id) REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE;


--
-- Name: cbom_components cbom_components_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_components
    ADD CONSTRAINT cbom_components_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: cbom_posture_summary cbom_posture_summary_asset_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary
    ADD CONSTRAINT cbom_posture_summary_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: cbom_posture_summary cbom_posture_summary_last_source_bom_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary
    ADD CONSTRAINT cbom_posture_summary_last_source_bom_id_fkey FOREIGN KEY (last_source_bom_id) REFERENCES ${tenantSchema}.bom_ingestion_records(id);


--
-- Name: cbom_posture_summary cbom_posture_summary_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_posture_summary
    ADD CONSTRAINT cbom_posture_summary_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: cbom_risk_findings cbom_risk_findings_cbom_component_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_risk_findings
    ADD CONSTRAINT cbom_risk_findings_cbom_component_id_fkey FOREIGN KEY (cbom_component_id) REFERENCES ${tenantSchema}.cbom_components(id) ON DELETE CASCADE;


--
-- Name: cbom_risk_findings cbom_risk_findings_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cbom_risk_findings
    ADD CONSTRAINT cbom_risk_findings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: demo_requests demo_requests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_requests
    ADD CONSTRAINT demo_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_comments finding_comments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_comments
    ADD CONSTRAINT finding_comments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_delta_queue finding_delta_queue_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_delta_queue
    ADD CONSTRAINT finding_delta_queue_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_events finding_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_events
    ADD CONSTRAINT finding_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_list_projection finding_list_projection_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_list_projection
    ADD CONSTRAINT finding_list_projection_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_reviews finding_reviews_finding_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_reviews
    ADD CONSTRAINT finding_reviews_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES ${tenantSchema}.findings(id) ON DELETE CASCADE;


--
-- Name: finding_reviews finding_reviews_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_reviews
    ADD CONSTRAINT finding_reviews_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_subjects finding_subjects_finding_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_subjects
    ADD CONSTRAINT finding_subjects_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES ${tenantSchema}.findings(id) ON DELETE CASCADE;


--
-- Name: finding_subjects finding_subjects_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_subjects
    ADD CONSTRAINT finding_subjects_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_workspace_projection_status finding_workspace_projection_status_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_workspace_projection_status
    ADD CONSTRAINT finding_workspace_projection_status_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: applicability_assessments fk_applicability_assessments_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.applicability_assessments
    ADD CONSTRAINT fk_applicability_assessments_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: applicability_assessments fk_applicability_assessments_vulnerability; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.applicability_assessments
    ADD CONSTRAINT fk_applicability_assessments_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: assets fk_assets_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.assets
    ADD CONSTRAINT fk_assets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: audit_events fk_audit_events_actor_user; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.audit_events
    ADD CONSTRAINT fk_audit_events_actor_user FOREIGN KEY (actor_user_id) REFERENCES platform.app_users(id);


--
-- Name: audit_events fk_audit_events_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.audit_events
    ADD CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: aws_discovery_configs fk_aws_discovery_configs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_configs
    ADD CONSTRAINT fk_aws_discovery_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: aws_discovery_targets fk_aws_discovery_targets_config; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_targets
    ADD CONSTRAINT fk_aws_discovery_targets_config FOREIGN KEY (config_id) REFERENCES ${tenantSchema}.aws_discovery_configs(id);


--
-- Name: aws_discovery_targets fk_aws_discovery_targets_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.aws_discovery_targets
    ADD CONSTRAINT fk_aws_discovery_targets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: azure_discovery_configs fk_azure_discovery_configs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_configs
    ADD CONSTRAINT fk_azure_discovery_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: azure_discovery_targets fk_azure_discovery_targets_config; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_targets
    ADD CONSTRAINT fk_azure_discovery_targets_config FOREIGN KEY (config_id) REFERENCES ${tenantSchema}.azure_discovery_configs(id);


--
-- Name: azure_discovery_targets fk_azure_discovery_targets_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.azure_discovery_targets
    ADD CONSTRAINT fk_azure_discovery_targets_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: bom_ingestion_records fk_bom_ir_previous_bom; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.bom_ingestion_records
    ADD CONSTRAINT fk_bom_ir_previous_bom FOREIGN KEY (previous_bom_id) REFERENCES ${tenantSchema}.bom_ingestion_records(id);


--
-- Name: ci_aliases fk_ci_aliases_ci; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ci_aliases
    ADD CONSTRAINT fk_ci_aliases_ci FOREIGN KEY (ci_id) REFERENCES ${tenantSchema}.cis(id);


--
-- Name: ci_aliases fk_ci_aliases_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ci_aliases
    ADD CONSTRAINT fk_ci_aliases_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: cis fk_cis_asset; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cis
    ADD CONSTRAINT fk_cis_asset FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: cis fk_cis_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.cis
    ADD CONSTRAINT fk_cis_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: component_vulnerability_states fk_component_vulnerability_states_component; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states
    ADD CONSTRAINT fk_component_vulnerability_states_component FOREIGN KEY (component_id) REFERENCES ${tenantSchema}.inventory_components(id);


--
-- Name: component_vulnerability_states fk_component_vulnerability_states_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states
    ADD CONSTRAINT fk_component_vulnerability_states_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: component_vulnerability_states fk_component_vulnerability_states_vulnerability; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.component_vulnerability_states
    ADD CONSTRAINT fk_component_vulnerability_states_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: dashboard_noise_reduction_projection fk_dashboard_noise_reduction_projection_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.dashboard_noise_reduction_projection
    ADD CONSTRAINT fk_dashboard_noise_reduction_projection_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) ON DELETE CASCADE;


--
-- Name: demo_invites fk_demo_invites_request; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_invites
    ADD CONSTRAINT fk_demo_invites_request FOREIGN KEY (request_id) REFERENCES ${tenantSchema}.demo_requests(id);


--
-- Name: demo_invites fk_demo_invites_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.demo_invites
    ADD CONSTRAINT fk_demo_invites_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: discovery_models fk_discovery_models_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.discovery_models
    ADD CONSTRAINT fk_discovery_models_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: finding_comments fk_finding_comments_finding; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_comments
    ADD CONSTRAINT fk_finding_comments_finding FOREIGN KEY (finding_id) REFERENCES ${tenantSchema}.findings(id);


--
-- Name: finding_events fk_finding_events_finding; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.finding_events
    ADD CONSTRAINT fk_finding_events_finding FOREIGN KEY (finding_id) REFERENCES ${tenantSchema}.findings(id);


--
-- Name: findings fk_findings_asset; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.findings
    ADD CONSTRAINT fk_findings_asset FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: findings fk_findings_component; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.findings
    ADD CONSTRAINT fk_findings_component FOREIGN KEY (component_id) REFERENCES ${tenantSchema}.inventory_components(id);


--
-- Name: findings fk_findings_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.findings
    ADD CONSTRAINT fk_findings_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: findings fk_findings_vulnerability; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.findings
    ADD CONSTRAINT fk_findings_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: fix_records fk_fix_records_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.fix_records
    ADD CONSTRAINT fk_fix_records_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: github_sbom_sources fk_github_sbom_sources_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.github_sbom_sources
    ADD CONSTRAINT fk_github_sbom_sources_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ingestion_jobs fk_ingestion_jobs_sbom_upload; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ingestion_jobs
    ADD CONSTRAINT fk_ingestion_jobs_sbom_upload FOREIGN KEY (sbom_upload_id) REFERENCES ${tenantSchema}.sbom_uploads(id);


--
-- Name: ingestion_jobs fk_ingestion_jobs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ingestion_jobs
    ADD CONSTRAINT fk_ingestion_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: inventory_component_cpe_map fk_inventory_component_cpe_map_component; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map
    ADD CONSTRAINT fk_inventory_component_cpe_map_component FOREIGN KEY (component_id) REFERENCES ${tenantSchema}.inventory_components(id);


--
-- Name: inventory_component_cpe_map fk_inventory_component_cpe_map_cpe; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map
    ADD CONSTRAINT fk_inventory_component_cpe_map_cpe FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim(id);


--
-- Name: inventory_component_cpe_map fk_inventory_component_cpe_map_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_component_cpe_map
    ADD CONSTRAINT fk_inventory_component_cpe_map_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: inventory_components fk_inventory_components_asset; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT fk_inventory_components_asset FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: inventory_components fk_inventory_components_manual_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT fk_inventory_components_manual_identity FOREIGN KEY (manual_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: inventory_components fk_inventory_components_sbom_upload; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT fk_inventory_components_sbom_upload FOREIGN KEY (sbom_upload_id) REFERENCES ${tenantSchema}.sbom_uploads(id);


--
-- Name: inventory_components fk_inventory_components_software_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT fk_inventory_components_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: inventory_components fk_inventory_components_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.inventory_components
    ADD CONSTRAINT fk_inventory_components_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: investigation_activities fk_investigation_activities_investigation; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_activities
    ADD CONSTRAINT fk_investigation_activities_investigation FOREIGN KEY (investigation_id) REFERENCES ${tenantSchema}.investigations(id);


--
-- Name: investigation_attachments fk_investigation_attachments_investigation; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_attachments
    ADD CONSTRAINT fk_investigation_attachments_investigation FOREIGN KEY (investigation_id) REFERENCES ${tenantSchema}.investigations(id);


--
-- Name: investigations fk_investigations_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigations
    ADD CONSTRAINT fk_investigations_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: investigations fk_investigations_vulnerability; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigations
    ADD CONSTRAINT fk_investigations_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: org_cve_ai_artifacts fk_org_cve_ai_artifacts_org_cve_record; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_ai_artifacts
    ADD CONSTRAINT fk_org_cve_ai_artifacts_org_cve_record FOREIGN KEY (org_cve_record_id) REFERENCES ${tenantSchema}.org_cve_records(id);


--
-- Name: org_cve_records fk_org_cve_records_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_records
    ADD CONSTRAINT fk_org_cve_records_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: org_cve_records fk_org_cve_records_vulnerability; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_records
    ADD CONSTRAINT fk_org_cve_records_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: ownership_rules fk_ownership_rules_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.ownership_rules
    ADD CONSTRAINT fk_ownership_rules_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: quality_issue_projection fk_quality_issue_projection_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.quality_issue_projection
    ADD CONSTRAINT fk_quality_issue_projection_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) ON DELETE CASCADE;


--
-- Name: risk_policies fk_risk_policies_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.risk_policies
    ADD CONSTRAINT fk_risk_policies_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: sbom_uploads fk_sbom_uploads_asset; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sbom_uploads
    ADD CONSTRAINT fk_sbom_uploads_asset FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: sbom_uploads fk_sbom_uploads_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sbom_uploads
    ADD CONSTRAINT fk_sbom_uploads_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: sccm_cmdb_configs fk_sccm_cmdb_configs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.sccm_cmdb_configs
    ADD CONSTRAINT fk_sccm_cmdb_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: service_accounts fk_service_accounts_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.service_accounts
    ADD CONSTRAINT fk_service_accounts_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: servicenow_cmdb_configs fk_servicenow_cmdb_configs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.servicenow_cmdb_configs
    ADD CONSTRAINT fk_servicenow_cmdb_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: software_identity_cluster_link fk_software_identity_cluster_link_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_cluster_link
    ADD CONSTRAINT fk_software_identity_cluster_link_identity FOREIGN KEY (target_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: software_identity_cluster_link fk_software_identity_cluster_link_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_cluster_link
    ADD CONSTRAINT fk_software_identity_cluster_link_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: software_identity_metadata fk_software_identity_metadata_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_metadata
    ADD CONSTRAINT fk_software_identity_metadata_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: software_identity_metadata fk_software_identity_metadata_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_metadata
    ADD CONSTRAINT fk_software_identity_metadata_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: software_identity_summary fk_software_identity_summary_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_summary
    ADD CONSTRAINT fk_software_identity_summary_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: software_identity_summary fk_software_identity_summary_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_identity_summary
    ADD CONSTRAINT fk_software_identity_summary_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: software_instances fk_software_instances_ci; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT fk_software_instances_ci FOREIGN KEY (ci_id) REFERENCES ${tenantSchema}.cis(id);


--
-- Name: software_instances fk_software_instances_discovery_model; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT fk_software_instances_discovery_model FOREIGN KEY (discovery_model_id) REFERENCES ${tenantSchema}.discovery_models(id);


--
-- Name: software_instances fk_software_instances_inventory_component; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT fk_software_instances_inventory_component FOREIGN KEY (inventory_component_id) REFERENCES ${tenantSchema}.inventory_components(id);


--
-- Name: software_instances fk_software_instances_software_identity; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT fk_software_instances_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: software_instances fk_software_instances_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_instances
    ADD CONSTRAINT fk_software_instances_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: software_inventory_items fk_software_inventory_items_asset; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items
    ADD CONSTRAINT fk_software_inventory_items_asset FOREIGN KEY (asset_id) REFERENCES ${tenantSchema}.assets(id);


--
-- Name: software_inventory_items fk_software_inventory_items_component; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items
    ADD CONSTRAINT fk_software_inventory_items_component FOREIGN KEY (component_id) REFERENCES ${tenantSchema}.inventory_components(id);


--
-- Name: software_inventory_items fk_software_inventory_items_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.software_inventory_items
    ADD CONSTRAINT fk_software_inventory_items_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: suppression_rules fk_suppression_rules_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.suppression_rules
    ADD CONSTRAINT fk_suppression_rules_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: vulnerability_source_filter_configs fk_vulnerability_source_filter_configs_tenant; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.vulnerability_source_filter_configs
    ADD CONSTRAINT fk_vulnerability_source_filter_configs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: investigation_activities investigation_activities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_activities
    ADD CONSTRAINT investigation_activities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: investigation_attachments investigation_attachments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_attachments
    ADD CONSTRAINT investigation_attachments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: investigation_runbook investigation_runbook_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.investigation_runbook
    ADD CONSTRAINT investigation_runbook_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: org_cve_ai_artifacts org_cve_ai_artifacts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ONLY ${tenantSchema}.org_cve_ai_artifacts
    ADD CONSTRAINT org_cve_ai_artifacts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_artifact_classifications; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_artifact_classifications ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_assessments; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_assessments ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_budget_admissions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_budget_admissions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_budget_alerts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_budget_alerts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_budget_config; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_budget_config ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_capability_observations; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_capability_observations ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_coverage_gaps; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_coverage_gaps ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_current_coverage_artifacts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_current_coverage_artifacts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_current_coverage_state; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_current_coverage_state ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_current_expected_candidates; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_current_expected_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_evidence_holds; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_evidence_holds ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_exposure_associations; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_exposure_associations ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_exposure_dispositions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_exposure_dispositions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_exposure_executions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_exposure_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_exposure_observations; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_exposure_observations ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_exposure_paths; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_exposure_paths ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_facts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_facts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_host_context_facts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_host_context_facts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_outbox; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_owner_history; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_owner_history ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_artifact_overrides; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_artifact_overrides ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_parameters; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_parameters ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_readiness; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_readiness ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_scopes; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_scopes ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_selection_history; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_selection_history ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_policy_selections; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_policy_selections ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_relationship_snapshots; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_relationship_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_retention_decisions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_retention_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_retention_policies; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_retention_policies ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_retention_purge_audit; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_retention_purge_audit ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_run_metrics; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_run_metrics ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_run_scope_metrics; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_run_scope_metrics ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_scan_cadence_rules; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_scan_cadence_rules ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_setup_actions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_setup_actions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_snapshot_bodies; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_snapshot_bodies ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_snapshot_manifests; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_snapshot_manifests ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_lineage_events; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_lineage_events ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_lineage_participants; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_lineage_participants ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_membership_decisions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_membership_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_membership_overrides; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_membership_overrides ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_memberships; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_memberships ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_system_revisions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_system_revisions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_systems; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_grid_systems ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_artifact_sources; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_artifact_sources ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_artifacts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_artifacts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_azure_credential_profiles; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_azure_credential_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_connector_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_connector_configs ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_observation_receipts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_observation_receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_relationships; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_relationships ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_security_snapshot_scopes; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ai_security_snapshot_scopes ENABLE ROW LEVEL SECURITY;

--
-- Name: applicability_assessments; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.applicability_assessments ENABLE ROW LEVEL SECURITY;

--
-- Name: assets; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.assets ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_events; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.audit_events ENABLE ROW LEVEL SECURITY;

--
-- Name: aws_discovery_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.aws_discovery_configs ENABLE ROW LEVEL SECURITY;

--
-- Name: aws_discovery_targets; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.aws_discovery_targets ENABLE ROW LEVEL SECURITY;

--
-- Name: azure_discovery_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.azure_discovery_configs ENABLE ROW LEVEL SECURITY;

--
-- Name: azure_discovery_targets; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.azure_discovery_targets ENABLE ROW LEVEL SECURITY;

--
-- Name: bom_component_evidence; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.bom_component_evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: bom_component_vulnerability_links; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.bom_component_vulnerability_links ENABLE ROW LEVEL SECURITY;

--
-- Name: bom_component_workflows; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.bom_component_workflows ENABLE ROW LEVEL SECURITY;

--
-- Name: bom_components; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.bom_components ENABLE ROW LEVEL SECURITY;

--
-- Name: bom_ingestion_records; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.bom_ingestion_records ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_activities; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_activities ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_delivery_attempts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_delivery_attempts ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_exceptions; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_exceptions ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_notes; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_notes ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_notify_groups; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_notify_groups ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_vulnerabilities; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_vulnerabilities ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_watchlist_entries; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaign_watchlist_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: campaigns; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.campaigns ENABLE ROW LEVEL SECURITY;

--
-- Name: cbom_components; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.cbom_components ENABLE ROW LEVEL SECURITY;

--
-- Name: cbom_posture_summary; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.cbom_posture_summary ENABLE ROW LEVEL SECURITY;

--
-- Name: cbom_risk_findings; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.cbom_risk_findings ENABLE ROW LEVEL SECURITY;

--
-- Name: ci_aliases; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ci_aliases ENABLE ROW LEVEL SECURITY;

--
-- Name: cis; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.cis ENABLE ROW LEVEL SECURITY;

--
-- Name: component_vulnerability_states; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.component_vulnerability_states ENABLE ROW LEVEL SECURITY;

--
-- Name: dashboard_noise_reduction_projection; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.dashboard_noise_reduction_projection ENABLE ROW LEVEL SECURITY;

--
-- Name: demo_invites; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.demo_invites ENABLE ROW LEVEL SECURITY;

--
-- Name: discovery_models; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.discovery_models ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_comments; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_comments ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_delta_queue; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_delta_queue ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_events; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_events ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_list_projection; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_list_projection ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_reviews; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_reviews ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_subjects; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_subjects ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_workspace_projection_status; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.finding_workspace_projection_status ENABLE ROW LEVEL SECURITY;

--
-- Name: findings; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.findings ENABLE ROW LEVEL SECURITY;

--
-- Name: fix_records; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.fix_records ENABLE ROW LEVEL SECURITY;

--
-- Name: github_sbom_sources; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.github_sbom_sources ENABLE ROW LEVEL SECURITY;

--
-- Name: ingestion_jobs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ingestion_jobs ENABLE ROW LEVEL SECURITY;

--
-- Name: inventory_component_cpe_map; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.inventory_component_cpe_map ENABLE ROW LEVEL SECURITY;

--
-- Name: inventory_components; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.inventory_components ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_activities; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigation_activities ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_attachments; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigation_attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_runbook; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigation_runbook ENABLE ROW LEVEL SECURITY;

--
-- Name: investigations; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.investigations ENABLE ROW LEVEL SECURITY;

--
-- Name: org_cve_ai_artifacts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.org_cve_ai_artifacts ENABLE ROW LEVEL SECURITY;

--
-- Name: org_cve_records; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.org_cve_records ENABLE ROW LEVEL SECURITY;

--
-- Name: ownership_rules; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.ownership_rules ENABLE ROW LEVEL SECURITY;

--
-- Name: quality_issue_projection; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.quality_issue_projection ENABLE ROW LEVEL SECURITY;

--
-- Name: risk_policies; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.risk_policies ENABLE ROW LEVEL SECURITY;

--
-- Name: sbom_uploads; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.sbom_uploads ENABLE ROW LEVEL SECURITY;

--
-- Name: sccm_cmdb_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.sccm_cmdb_configs ENABLE ROW LEVEL SECURITY;

--
-- Name: service_accounts; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.service_accounts ENABLE ROW LEVEL SECURITY;

--
-- Name: servicenow_cmdb_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.servicenow_cmdb_configs ENABLE ROW LEVEL SECURITY;

--
-- Name: software_identity_cluster_link; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.software_identity_cluster_link ENABLE ROW LEVEL SECURITY;

--
-- Name: software_identity_metadata; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.software_identity_metadata ENABLE ROW LEVEL SECURITY;

--
-- Name: software_identity_summary; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.software_identity_summary ENABLE ROW LEVEL SECURITY;

--
-- Name: software_instances; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.software_instances ENABLE ROW LEVEL SECURITY;

--
-- Name: software_inventory_items; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.software_inventory_items ENABLE ROW LEVEL SECURITY;

--
-- Name: suppression_rules; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.suppression_rules ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_grid_artifact_classifications tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_artifact_classifications USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_assessments tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_assessments USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_budget_admissions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_budget_admissions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_budget_alerts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_budget_alerts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_budget_config tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_budget_config USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_capability_observations tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_capability_observations USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_coverage_gaps tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_coverage_gaps USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_current_coverage_artifacts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_current_coverage_artifacts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_current_coverage_state tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_current_coverage_state USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_current_expected_candidates tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_current_expected_candidates USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_evidence_holds tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_evidence_holds USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_exposure_associations tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_exposure_associations USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_exposure_dispositions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_exposure_dispositions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_exposure_executions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_exposure_executions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_exposure_observations tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_exposure_observations USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_exposure_paths tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_exposure_paths USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_facts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_facts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_host_context_facts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_host_context_facts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_outbox tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_outbox USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_owner_history tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_owner_history USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_artifact_overrides tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_artifact_overrides USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_parameters tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_parameters USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_readiness tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_readiness USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_scopes tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_scopes USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_selection_history tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_selection_history USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_policy_selections tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_policy_selections USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_relationship_snapshots tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_relationship_snapshots USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_retention_decisions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_retention_decisions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_retention_policies tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_retention_policies USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_retention_purge_audit tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_retention_purge_audit USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_run_metrics tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_run_metrics USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_run_scope_metrics tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_run_scope_metrics USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_scan_cadence_rules tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_scan_cadence_rules USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_setup_actions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_setup_actions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_snapshot_bodies tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_snapshot_bodies USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_snapshot_manifests tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_snapshot_manifests USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_lineage_events tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_lineage_events USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_lineage_participants tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_lineage_participants USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_membership_decisions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_membership_decisions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_membership_overrides tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_membership_overrides USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_memberships tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_memberships USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_system_revisions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_system_revisions USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_grid_systems tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_systems USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_artifact_sources tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_artifact_sources USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_artifacts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_artifacts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_azure_credential_profiles tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_azure_credential_profiles USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_connector_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_connector_configs USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_observation_receipts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_observation_receipts USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_relationships tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_relationships USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: ai_security_snapshot_scopes tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_snapshot_scopes USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: applicability_assessments tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.applicability_assessments USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: assets tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.assets USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: audit_events tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.audit_events USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text) IS NULL)))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text) IS NULL))));


--
-- Name: aws_discovery_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.aws_discovery_configs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: aws_discovery_targets tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.aws_discovery_targets USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: azure_discovery_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.azure_discovery_configs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: azure_discovery_targets tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.azure_discovery_targets USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: bom_component_evidence tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_component_evidence USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: bom_component_vulnerability_links tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_component_vulnerability_links USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: bom_component_workflows tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_component_workflows USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: bom_components tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_components USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: bom_ingestion_records tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_ingestion_records USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_activities tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_activities USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_delivery_attempts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_delivery_attempts USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_exceptions tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_exceptions USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_notes tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_notes USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_notify_groups tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_notify_groups USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_vulnerabilities tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_vulnerabilities USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaign_watchlist_entries tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_watchlist_entries USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: campaigns tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.campaigns USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: cbom_components tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_components USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: cbom_posture_summary tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_posture_summary USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: cbom_risk_findings tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_risk_findings USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: ci_aliases tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ci_aliases USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: cis tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.cis USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: component_vulnerability_states tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.component_vulnerability_states USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: dashboard_noise_reduction_projection tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.dashboard_noise_reduction_projection USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: demo_invites tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.demo_invites USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: discovery_models tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.discovery_models USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: finding_comments tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_comments USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: finding_delta_queue tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_delta_queue USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: finding_events tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_events USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: finding_list_projection tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_list_projection USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: finding_reviews tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_reviews USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: finding_subjects tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_subjects USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: finding_workspace_projection_status tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_workspace_projection_status USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid));


--
-- Name: findings tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.findings USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: fix_records tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_records USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: github_sbom_sources tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.github_sbom_sources USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: ingestion_jobs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ingestion_jobs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: inventory_component_cpe_map tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.inventory_component_cpe_map USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: inventory_components tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.inventory_components USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: investigation_activities tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.investigation_activities USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: investigation_attachments tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.investigation_attachments USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: investigation_runbook tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.investigation_runbook USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: investigations tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.investigations USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: org_cve_ai_artifacts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.org_cve_ai_artifacts USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: org_cve_records tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.org_cve_records USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: ownership_rules tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_rules USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: quality_issue_projection tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.quality_issue_projection USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: risk_policies tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.risk_policies USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: sbom_uploads tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.sbom_uploads USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: sccm_cmdb_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.sccm_cmdb_configs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: service_accounts tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.service_accounts USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: servicenow_cmdb_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.servicenow_cmdb_configs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: software_identity_cluster_link tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.software_identity_cluster_link USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: software_identity_metadata tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.software_identity_metadata USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: software_identity_summary tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.software_identity_summary USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: software_instances tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.software_instances USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: software_inventory_items tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.software_inventory_items USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: suppression_rules tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.suppression_rules USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: vulnerability_source_filter_configs tenant_isolation; Type: POLICY; Schema: ${tenantSchema}; Owner: -
--

CREATE POLICY tenant_isolation ON ${tenantSchema}.vulnerability_source_filter_configs USING ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK ((((NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid = 'e5fe0d29-1d64-4175-8ce6-c34f42b214cc'::uuid) AND (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: vulnerability_source_filter_configs; Type: ROW SECURITY; Schema: ${tenantSchema}; Owner: -
--

ALTER TABLE ${tenantSchema}.vulnerability_source_filter_configs ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
-- The baseline is installed by the schema owner before a tenant session exists.
-- Temporarily let that owner bypass the policy while it creates the default
-- budget row; the table is forced back to RLS immediately afterwards.
ALTER TABLE ${tenantSchema}.ai_grid_budget_config NO FORCE ROW LEVEL SECURITY;

INSERT INTO ${tenantSchema}.ai_grid_budget_config
    (tenant_id, enforcement_mode, daily_scan_limit, daily_provider_api_call_limit,
     daily_new_snapshot_bytes_limit, daily_processing_ms_limit, retained_snapshot_bytes_limit,
     warning_ratio, updated_by, reason)
VALUES ((SELECT id FROM platform.tenants WHERE schema_name = '${tenantSchema}' LIMIT 1),
        'OBSERVE', 24, 10000, 1073741824, 3600000, 10737418240,
        0.80, 'ai-grid-bootstrap', 'Initial observable AI Grid budget')
ON CONFLICT (tenant_id) DO NOTHING;

ALTER TABLE ${tenantSchema}.ai_grid_budget_config FORCE ROW LEVEL SECURITY;

-- PostgreSQL database dump complete
-- Add tenant-parameterized access for newly provisioned schemas. The dump's
-- default-workspace policies remain for compatibility; this permissive policy
-- makes the same schema safe for its actual platform tenant ID.
DO $$
DECLARE table_record record;
BEGIN
    FOR table_record IN
        SELECT table_name
          FROM information_schema.columns
         WHERE table_schema = '${tenantSchema}'
           AND column_name = 'tenant_id'
    LOOP
        EXECUTE format(
            'CREATE POLICY tenant_runtime_isolation ON %I.%I '
            'USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid) '
            'WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
            '${tenantSchema}', table_record.table_name);
    END LOOP;
END $$;
--
