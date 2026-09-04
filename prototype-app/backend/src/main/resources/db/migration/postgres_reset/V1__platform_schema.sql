-- migration-guard: platform-only
-- Generated from a disposable PostgreSQL schema-only dump; no runtime data.
-- PostgreSQL database dump
--


-- Dumped from database version 17.9 (Homebrew)
-- Dumped by pg_dump version 17.9 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: platform; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA IF NOT EXISTS platform;
CREATE SCHEMA IF NOT EXISTS tenant_default;


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA IF NOT EXISTS public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: ai_grid_approved_decision_matches(character varying, character varying, character varying, uuid); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.ai_grid_approved_decision_matches(candidate_policy_id character varying, candidate_version character varying, candidate_digest character varying, candidate_decision uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT candidate_digest IS NOT NULL AND btrim(candidate_digest) <> ''
       AND candidate_decision IS NOT NULL
       AND EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions d
                    WHERE d.id = candidate_decision AND d.policy_id = candidate_policy_id
                      AND d.policy_version = candidate_version AND d.package_digest = candidate_digest
                      AND d.decision = 'APPROVED' AND d.revoked_at IS NULL)
$$;


--
-- Name: ai_grid_policy_release_decisions_immutable(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.ai_grid_policy_release_decisions_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'AI Grid policy release decisions are immutable';
END;
$$;


--
-- Name: invalidate_ai_grid_phase_1_preview_on_digest_change(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change() RETURNS trigger
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


--
-- Name: pause_ai_grid_revoked_distribution(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.pause_ai_grid_revoked_distribution() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
        UPDATE platform.ai_grid_policy_distribution
           SET available=false, rollout_stage='PAUSED', default_selection='DISABLED',
               canary_tenant_ids_json='[]'::jsonb, updated_by=coalesce(NEW.revoked_by, 'ai-grid-revocation'), updated_at=now()
         WHERE policy_id=NEW.policy_id AND release_decision_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;


--
-- Name: prevent_ai_grid_approved_package_mutation(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.prevent_ai_grid_approved_package_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
       AND OLD.package_digest IS NOT NULL
       AND OLD.package_source_ref LIKE 'policy-packages/agcf/%' AND (
       OLD.name IS DISTINCT FROM NEW.name OR OLD.description IS DISTINCT FROM NEW.description OR
       OLD.severity IS DISTINCT FROM NEW.severity OR OLD.workflow_class IS DISTINCT FROM NEW.workflow_class OR
       OLD.default_selection IS DISTINCT FROM NEW.default_selection OR OLD.artifact_types_json IS DISTINCT FROM NEW.artifact_types_json OR
       OLD.native_kinds_json IS DISTINCT FROM NEW.native_kinds_json OR OLD.required_capabilities_json IS DISTINCT FROM NEW.required_capabilities_json OR
       OLD.required_relationships_json IS DISTINCT FROM NEW.required_relationships_json OR OLD.required_resource_families_json IS DISTINCT FROM NEW.required_resource_families_json OR
       OLD.required_facts_json IS DISTINCT FROM NEW.required_facts_json OR OLD.predicate_json IS DISTINCT FROM NEW.predicate_json OR
       OLD.reason_code IS DISTINCT FROM NEW.reason_code OR OLD.remediation IS DISTINCT FROM NEW.remediation OR
       OLD.framework_mappings_json IS DISTINCT FROM NEW.framework_mappings_json OR OLD.scope_resolution IS DISTINCT FROM NEW.scope_resolution OR
       OLD.parameter_definitions_json IS DISTINCT FROM NEW.parameter_definitions_json OR OLD.package_digest IS DISTINCT FROM NEW.package_digest OR
       OLD.package_source_ref IS DISTINCT FROM NEW.package_source_ref OR OLD.release_notes IS DISTINCT FROM NEW.release_notes OR
       OLD.release_family IS DISTINCT FROM NEW.release_family OR OLD.release_wave IS DISTINCT FROM NEW.release_wave) THEN
        RAISE EXCEPTION 'Approved, canary, published, or deprecated policy packages are immutable';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: reject_ai_grid_release_manifest_mutation(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.reject_ai_grid_release_manifest_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
    RAISE EXCEPTION 'AI Grid release manifests are immutable';
END $$;


--
-- Name: require_ai_grid_approved_package(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.require_ai_grid_approved_package() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.lifecycle IN ('APPROVED','CANARY','PUBLISHED','DEPRECATED')
       AND NEW.package_digest IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_release_decisions d
                       WHERE d.policy_id = NEW.policy_id AND d.policy_version = NEW.version
                         AND d.package_digest = NEW.package_digest AND d.decision = 'APPROVED'
                         AND d.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Active policy lifecycle requires an exact unrevoked approval and digest';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: require_ai_grid_distribution_approval(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.require_ai_grid_distribution_approval() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE pinned platform.ai_grid_policy_versions%ROWTYPE;
BEGIN
    IF NEW.rollout_stage = 'DEV' THEN
        IF NEW.pinned_version IS NULL THEN RAISE EXCEPTION 'Dev distribution requires a pinned version'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.available OR NEW.rollout_stage IN ('GENERAL_AVAILABILITY','CANARY') OR NEW.pinned_version IS NOT NULL THEN
        IF NEW.pinned_version IS NULL THEN RAISE EXCEPTION 'Active distribution requires a pinned version'; END IF;
        SELECT * INTO pinned FROM platform.ai_grid_policy_versions
         WHERE policy_id = NEW.policy_id AND version = NEW.pinned_version;
        IF FOUND AND pinned.package_digest IS NULL THEN RETURN NEW; END IF;
        IF NOT FOUND OR pinned.lifecycle NOT IN ('PUBLISHED','CANARY','DEPRECATED')
           OR NOT platform.ai_grid_approved_decision_matches(NEW.policy_id, NEW.pinned_version,
                                                              NEW.approved_package_digest, NEW.release_decision_id)
           OR pinned.package_digest <> NEW.approved_package_digest THEN
            RAISE EXCEPTION 'Distribution requires an exact unrevoked approval binding';
        END IF;
    END IF;
    RETURN NEW;
END $$;


--
-- Name: require_ai_grid_rollout_approval(); Type: FUNCTION; Schema: platform; Owner: -
--

CREATE FUNCTION platform.require_ai_grid_rollout_approval() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT platform.ai_grid_approved_decision_matches(NEW.policy_id, NEW.new_version,
                                                       NEW.approved_package_digest, NEW.release_decision_id)
       OR NEW.package_digest <> NEW.approved_package_digest THEN
        RAISE EXCEPTION 'Rollout requires an exact unrevoked approval binding';
    END IF;
    RETURN NEW;
END $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ai_grid_answer_key_cases; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_answer_key_cases (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    case_key character varying(160) NOT NULL,
    scenario character varying(32) NOT NULL,
    policy_id character varying(128),
    policy_version character varying(32),
    expected_applicability character varying(32),
    expected_decision character varying(32),
    expected_finding boolean,
    expected_json jsonb NOT NULL,
    label_version character varying(32) NOT NULL,
    rationale text NOT NULL,
    evidence_reference text NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_answer_key_cases_check CHECK ((((policy_id IS NULL) AND (policy_version IS NULL)) OR ((policy_id IS NOT NULL) AND (policy_version IS NOT NULL)))),
    CONSTRAINT ai_grid_answer_key_cases_expected_applicability_check CHECK (((expected_applicability IS NULL) OR ((expected_applicability)::text = ANY ((ARRAY['APPLICABLE'::character varying, 'NOT_APPLICABLE'::character varying])::text[])))),
    CONSTRAINT ai_grid_answer_key_cases_expected_decision_check CHECK (((expected_decision IS NULL) OR ((expected_decision)::text = ANY ((ARRAY['PASS'::character varying, 'FAIL'::character varying, 'NO_DECISION'::character varying])::text[])))),
    CONSTRAINT ai_grid_answer_key_cases_scenario_check CHECK (((scenario)::text = ANY ((ARRAY['SECURE'::character varying, 'INSECURE'::character varying, 'PARTIAL'::character varying, 'DENIED'::character varying, 'THROTTLED'::character varying, 'STALE'::character varying, 'UNSUPPORTED'::character varying, 'DELETED'::character varying, 'RENAMED'::character varying, 'SPLIT'::character varying, 'MERGE'::character varying, 'REDISCOVERED'::character varying, 'PROXY_VS_VERIFIED'::character varying, 'OTHER'::character varying])::text[])))
);


--
-- Name: ai_grid_answer_key_environments; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_answer_key_environments (
    id uuid NOT NULL,
    environment_key character varying(128) NOT NULL,
    version character varying(32) NOT NULL,
    provider character varying(32) NOT NULL,
    resource_family character varying(128) NOT NULL,
    lifecycle character varying(32) DEFAULT 'DRAFT'::character varying NOT NULL,
    engineering_owner character varying(255) NOT NULL,
    security_reviewer character varying(255) NOT NULL,
    provider_api_versions_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    expected_economics_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    change_summary text NOT NULL,
    certified_at timestamp with time zone,
    last_verified_at timestamp with time zone,
    review_due_at timestamp with time zone NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_answer_key_environments_check CHECK ((review_due_at > created_at)),
    CONSTRAINT ai_grid_answer_key_environments_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['DRAFT'::character varying, 'CERTIFIED'::character varying, 'STALE'::character varying, 'RETIRED'::character varying])::text[])))
);


--
-- Name: ai_grid_answer_key_results; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_answer_key_results (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    case_id uuid NOT NULL,
    observed_json jsonb NOT NULL,
    matched boolean NOT NULL,
    mismatch_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_assessment_id uuid,
    source_decision_fingerprint character varying(64)
);


--
-- Name: ai_grid_answer_key_runs; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_answer_key_runs (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    catalog_digest character varying(128) NOT NULL,
    status character varying(32) NOT NULL,
    total_cases integer NOT NULL,
    matched_cases integer NOT NULL,
    executed_by character varying(255) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone DEFAULT now() NOT NULL,
    source_tenant_id uuid,
    source_run_id uuid,
    provenance_state character varying(32) DEFAULT 'EXTERNAL_ATTESTATION'::character varying NOT NULL,
    CONSTRAINT ai_grid_answer_key_run_provenance_state_check CHECK (((provenance_state)::text = ANY ((ARRAY['EXTERNAL_ATTESTATION'::character varying, 'PLATFORM_RUN_BOUND'::character varying])::text[]))),
    CONSTRAINT ai_grid_answer_key_runs_check CHECK (((matched_cases >= 0) AND (matched_cases <= total_cases))),
    CONSTRAINT ai_grid_answer_key_runs_status_check CHECK (((status)::text = ANY ((ARRAY['PASS'::character varying, 'FAIL'::character varying])::text[]))),
    CONSTRAINT ai_grid_answer_key_runs_total_cases_check CHECK ((total_cases > 0))
);


--
-- Name: ai_grid_capability_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_capability_definitions (
    capability_id character varying(128) NOT NULL,
    provider character varying(32) NOT NULL,
    connector character varying(128) NOT NULL,
    resource_family character varying(128) NOT NULL,
    optional boolean DEFAULT false NOT NULL,
    lifecycle character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    remediation text NOT NULL,
    CONSTRAINT ai_grid_capability_definitions_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['ACTIVE'::character varying, 'RETIRED'::character varying])::text[]))),
    CONSTRAINT ai_grid_capability_definitions_provider_check CHECK (((provider)::text = ANY ((ARRAY['AWS'::character varying, 'AZURE'::character varying, 'MULTI_CLOUD'::character varying])::text[])))
);


--
-- Name: ai_grid_control_objectives; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_control_objectives (
    control_objective_id character varying(128) NOT NULL,
    name character varying(512) NOT NULL,
    security_intent text NOT NULL,
    remediation_intent text NOT NULL,
    owner character varying(255) NOT NULL,
    lifecycle character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_control_objectives_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['DRAFT'::character varying, 'ACTIVE'::character varying, 'RETIRED'::character varying])::text[])))
);


--
-- Name: ai_grid_correlation_precision_reviews; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_correlation_precision_reviews (
    id uuid NOT NULL,
    correlation_id character varying(128) NOT NULL,
    correlation_version character varying(32) NOT NULL,
    material_digest character varying(128) NOT NULL,
    sample_size integer NOT NULL,
    accepted_samples integer NOT NULL,
    precision_value double precision NOT NULL,
    precision_threshold double precision NOT NULL,
    status character varying(32) NOT NULL,
    evidence_reference character varying(1024) NOT NULL,
    reviewed_by character varying(255) NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_correlation_precision_reviews_accepted_samples_check CHECK ((accepted_samples >= 0)),
    CONSTRAINT ai_grid_correlation_precision_reviews_precision_threshold_check CHECK (((precision_threshold >= (0)::double precision) AND (precision_threshold <= (1)::double precision))),
    CONSTRAINT ai_grid_correlation_precision_reviews_precision_value_check CHECK (((precision_value >= (0)::double precision) AND (precision_value <= (1)::double precision))),
    CONSTRAINT ai_grid_correlation_precision_reviews_sample_size_check CHECK ((sample_size > 0)),
    CONSTRAINT ai_grid_correlation_precision_reviews_status_check CHECK (((status)::text = ANY ((ARRAY['PASSED'::character varying, 'FAILED'::character varying, 'STALE'::character varying])::text[])))
);


--
-- Name: ai_grid_correlation_versions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_correlation_versions (
    correlation_id character varying(128) NOT NULL,
    version character varying(32) NOT NULL,
    name character varying(512) NOT NULL,
    description text NOT NULL,
    lifecycle character varying(32) NOT NULL,
    severity character varying(32) NOT NULL,
    precision_threshold double precision NOT NULL,
    max_path_depth integer NOT NULL,
    max_fan_out integer NOT NULL,
    allowed_node_types_json jsonb NOT NULL,
    allowed_edge_types_json jsonb NOT NULL,
    requirements_json jsonb NOT NULL,
    approved_by character varying(255),
    approved_at timestamp with time zone,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_correlation_versions_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['DRAFT'::character varying, 'APPROVED'::character varying, 'PUBLISHED'::character varying, 'RETIRED'::character varying])::text[]))),
    CONSTRAINT ai_grid_correlation_versions_max_fan_out_check CHECK (((max_fan_out >= 1) AND (max_fan_out <= 100))),
    CONSTRAINT ai_grid_correlation_versions_max_path_depth_check CHECK (((max_path_depth >= 1) AND (max_path_depth <= 6))),
    CONSTRAINT ai_grid_correlation_versions_precision_threshold_check CHECK (((precision_threshold >= (0)::double precision) AND (precision_threshold <= (1)::double precision)))
);


--
-- Name: ai_grid_fact_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_fact_definitions (
    fact_key character varying(255) NOT NULL,
    version character varying(32) NOT NULL,
    value_type character varying(32) NOT NULL,
    claim_semantics text NOT NULL,
    allowed_evidence_classes_json jsonb NOT NULL,
    allowed_workflow_uses_json jsonb NOT NULL,
    default_max_age_seconds bigint,
    lifecycle character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_grid_phase_1_preview_gate_evidence; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_phase_1_preview_gate_evidence (
    gate_key character varying(64) NOT NULL,
    status character varying(16) DEFAULT 'PENDING'::character varying NOT NULL,
    evidence_ref character varying(1024),
    results_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    recorded_by character varying(255),
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_phase_1_preview_gate_evidence_results_json_check CHECK ((jsonb_typeof(results_json) = 'object'::text)),
    CONSTRAINT ai_grid_phase_1_preview_gate_evidence_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'PASSED'::character varying, 'FAILED'::character varying])::text[])))
);


--
-- Name: ai_grid_phase_1_preview_release; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_phase_1_preview_release (
    release_family character varying(64) NOT NULL,
    manifest_digest character varying(64) NOT NULL,
    total_policies integer NOT NULL,
    state character varying(32) DEFAULT 'PAUSED'::character varying NOT NULL,
    internal_tenant_id uuid,
    approved_cohort_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_approved_cohort_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    approved_by character varying(255),
    approved_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_phase_1_preview_release_approved_cohort_json_check CHECK ((jsonb_typeof(approved_cohort_json) = 'array'::text)),
    CONSTRAINT ai_grid_phase_1_preview_release_last_approved_cohort_json_check CHECK ((jsonb_typeof(last_approved_cohort_json) = 'array'::text)),
    CONSTRAINT ai_grid_phase_1_preview_release_state_check CHECK (((state)::text = ANY ((ARRAY['PAUSED'::character varying, 'READY'::character varying, 'PROMOTED'::character varying, 'INVALIDATED'::character varying])::text[])))
);


--
-- Name: ai_grid_phase_1_release_gate_evidence; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_phase_1_release_gate_evidence (
    id uuid NOT NULL,
    gate_key character varying(64) NOT NULL,
    status character varying(16) NOT NULL,
    evidence_json jsonb NOT NULL,
    recorded_by character varying(255) NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_phase_1_release_gate_evidence_gate_key_check CHECK (((gate_key)::text = ANY ((ARRAY['CANARY_AWS'::character varying, 'CANARY_AZURE'::character varying, 'CANARY_MULTI_CLOUD'::character varying, 'PERFORMANCE'::character varying, 'ROLLBACK_AWS'::character varying, 'ROLLBACK_AZURE'::character varying, 'ROLLBACK_MULTI_CLOUD'::character varying])::text[]))),
    CONSTRAINT ai_grid_phase_1_release_gate_evidence_status_check CHECK (((status)::text = ANY ((ARRAY['PASSED'::character varying, 'FAILED'::character varying])::text[])))
);


--
-- Name: ai_grid_phase_1_tenant_migration_audit; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_phase_1_tenant_migration_audit (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    ledger_version character varying(64) NOT NULL,
    applied_by character varying(255) NOT NULL,
    legacy_selection_count integer NOT NULL,
    selection_copy_count integer NOT NULL,
    retirement_count integer NOT NULL,
    open_findings_closed integer NOT NULL,
    manual_configuration_review_count integer NOT NULL,
    actions_json jsonb NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_grid_policy_candidates; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_candidates (
    id uuid NOT NULL,
    title character varying(512) NOT NULL,
    source_type character varying(64) NOT NULL,
    status character varying(32) DEFAULT 'INTAKE'::character varying NOT NULL,
    technology_id character varying(128),
    rationale text NOT NULL,
    framework_mappings_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    risk_score integer NOT NULL,
    reach_score integer NOT NULL,
    evidence_maturity integer NOT NULL,
    remediation_clarity integer NOT NULL,
    owner character varying(255),
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_candidates_evidence_maturity_check CHECK (((evidence_maturity >= 1) AND (evidence_maturity <= 5))),
    CONSTRAINT ai_grid_policy_candidates_reach_score_check CHECK (((reach_score >= 1) AND (reach_score <= 5))),
    CONSTRAINT ai_grid_policy_candidates_remediation_clarity_check CHECK (((remediation_clarity >= 1) AND (remediation_clarity <= 5))),
    CONSTRAINT ai_grid_policy_candidates_risk_score_check CHECK (((risk_score >= 1) AND (risk_score <= 5))),
    CONSTRAINT ai_grid_policy_candidates_source_type_check CHECK (((source_type)::text = ANY ((ARRAY['CONNECTOR_CAPABILITY'::character varying, 'COVERAGE_GAP'::character varying, 'THREAT_RESEARCH'::character varying, 'CUSTOMER_REQUEST'::character varying, 'INCIDENT'::character varying, 'COMPLIANCE_FRAMEWORK'::character varying, 'DESIGN_PARTNER'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_candidates_status_check CHECK (((status)::text = ANY ((ARRAY['INTAKE'::character varying, 'RESEARCH'::character varying, 'COLLECTOR_BACKLOG'::character varying, 'READY_FOR_AUTHORING'::character varying, 'DECLINED'::character varying, 'SHIPPED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_deprecation_tasks; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_deprecation_tasks (
    id uuid NOT NULL,
    deprecation_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    state character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp with time zone,
    failure_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_deprecation_tasks_state_check CHECK (((state)::text = ANY ((ARRAY['PENDING'::character varying, 'PROCESSING'::character varying, 'COMPLETED'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_deprecations; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_deprecations (
    id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    reason text NOT NULL,
    successor_policy_id character varying(128),
    deprecated_by character varying(255) NOT NULL,
    deprecated_at timestamp with time zone DEFAULT now() NOT NULL,
    idempotency_key character varying(128) NOT NULL
);


--
-- Name: ai_grid_policy_dev_deployments; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_dev_deployments (
    id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    target_tenant_ids_json jsonb NOT NULL,
    test_note text NOT NULL,
    deployed_by character varying(255) NOT NULL,
    deployed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_grid_policy_distribution; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_distribution (
    policy_id character varying(128) NOT NULL,
    available boolean DEFAULT true NOT NULL,
    default_selection character varying(32) DEFAULT 'ENABLED'::character varying NOT NULL,
    rollout_stage character varying(32) DEFAULT 'GENERAL_AVAILABILITY'::character varying NOT NULL,
    canary_tenant_ids_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    pinned_version character varying(32),
    updated_by character varying(255) DEFAULT 'ai-grid-bootstrap'::character varying NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_package_digest character varying(64),
    release_decision_id uuid,
    CONSTRAINT ai_grid_policy_distribution_default_selection_check CHECK (((default_selection)::text = ANY ((ARRAY['REQUIRED'::character varying, 'ENABLED'::character varying, 'PREVIEW'::character varying, 'DISABLED'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_distribution_rollout_stage_check CHECK (((rollout_stage)::text = ANY ((ARRAY['GENERAL_AVAILABILITY'::character varying, 'CANARY'::character varying, 'DEV'::character varying, 'PAUSED'::character varying, 'RETIRED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_inactivation_tasks; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_inactivation_tasks (
    id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    tenant_id uuid NOT NULL,
    reason character varying(64) DEFAULT 'PLATFORM_DEPRECATED'::character varying NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp with time zone,
    failure_detail text,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_inactivation_tasks_reason_check CHECK (((reason)::text = 'PLATFORM_DEPRECATED'::text)),
    CONSTRAINT ai_grid_policy_inactivation_tasks_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'PROCESSING'::character varying, 'COMPLETED'::character varying, 'FAILED'::character varying, 'CANCELED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_migration_ledger; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_migration_ledger (
    legacy_detector_id character varying(128) NOT NULL,
    legacy_detector_kind character varying(32) NOT NULL,
    legacy_version character varying(32) DEFAULT '1.0.0'::character varying NOT NULL,
    disposition character varying(48) NOT NULL,
    successor_policy_ids_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    closure_reason character varying(128),
    rationale text NOT NULL,
    approved_by character varying(255) NOT NULL,
    approved_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_migration_ledger_check CHECK ((((disposition)::text = 'RETIRED_INSUFFICIENT_EVIDENCE'::text) = (closure_reason IS NOT NULL))),
    CONSTRAINT ai_grid_policy_migration_ledger_disposition_check CHECK (((disposition)::text = ANY ((ARRAY['ONE_TO_ONE_REPLACEMENT'::character varying, 'SPLIT_REPLACEMENT'::character varying, 'RETAINED_GOVERNED_ENVELOPE'::character varying, 'RETIRED_INSUFFICIENT_EVIDENCE'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_migration_ledger_legacy_detector_kind_check CHECK (((legacy_detector_kind)::text = ANY ((ARRAY['POSTURE_POLICY'::character varying, 'CORRELATION'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_release_bindings; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_release_bindings (
    id uuid NOT NULL,
    approval_decision_id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    approved_package_digest character varying(128) NOT NULL,
    distribution_snapshot_json jsonb NOT NULL,
    target_tenant_ids_json jsonb NOT NULL,
    bound_by character varying(255) NOT NULL,
    bound_at timestamp with time zone DEFAULT now() NOT NULL,
    state character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by character varying(255),
    revocation_reason text,
    CONSTRAINT ai_grid_policy_release_bindings_check CHECK (((((state)::text = 'ACTIVE'::text) AND (revoked_at IS NULL) AND (revoked_by IS NULL)) OR (((state)::text <> 'ACTIVE'::text) AND (revoked_at IS NOT NULL) AND (revoked_by IS NOT NULL)))),
    CONSTRAINT ai_grid_policy_release_bindings_state_check CHECK (((state)::text = ANY ((ARRAY['ACTIVE'::character varying, 'REVOKED'::character varying, 'CANCELLED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_release_decisions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_release_decisions (
    id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    decision character varying(32) NOT NULL,
    answer_key_run_id uuid,
    precision_review_id uuid,
    reason text NOT NULL,
    decided_by character varying(255) NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    package_digest character varying(64),
    revoked_at timestamp with time zone,
    revoked_by character varying(255),
    revocation_reason text,
    approved_package_digest character varying(128),
    CONSTRAINT ai_grid_policy_release_decisions_decision_check CHECK (((decision)::text = ANY ((ARRAY['APPROVED'::character varying, 'BLOCKED'::character varying])::text[]))),
    CONSTRAINT ai_grid_release_decision_digest_check CHECK ((((decision)::text <> 'APPROVED'::text) OR ((package_digest IS NOT NULL) AND (btrim((package_digest)::text) <> ''::text))))
);


--
-- Name: ai_grid_policy_replacements; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_replacements (
    predecessor_policy_id character varying(128) NOT NULL,
    successor_policy_id character varying(128) NOT NULL,
    release_family character varying(64) DEFAULT 'AGCF_PHASE_2'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_grid_policy_rollout_tasks; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_rollout_tasks (
    id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp with time zone,
    source_snapshot_run_id uuid,
    assessment_run_id uuid,
    failure_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_policy_rollout_tasks_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'PROCESSING'::character varying, 'WAITING_FOR_SNAPSHOT'::character varying, 'COMPLETED'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_rollouts; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_rollouts (
    id uuid NOT NULL,
    release_id character varying(128) NOT NULL,
    release_type character varying(64) NOT NULL,
    policy_id character varying(128) NOT NULL,
    previous_version character varying(32),
    new_version character varying(32) NOT NULL,
    package_digest character varying(64) NOT NULL,
    distribution_snapshot_json jsonb NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    approved_package_digest character varying(64),
    release_decision_id uuid,
    CONSTRAINT ai_grid_policy_rollouts_release_type_check CHECK (((release_type)::text = ANY ((ARRAY['INITIAL_CATALOG'::character varying, 'POLICY_VERSION'::character varying, 'REPLACEMENT'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_rollouts_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'PROCESSING'::character varying, 'COMPLETED'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying])::text[])))
);


--
-- Name: ai_grid_policy_versions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_policy_versions (
    policy_id character varying(128) NOT NULL,
    version character varying(32) NOT NULL,
    name character varying(512) NOT NULL,
    description text NOT NULL,
    severity character varying(32) NOT NULL,
    lifecycle character varying(32) NOT NULL,
    workflow_class character varying(32) NOT NULL,
    default_selection character varying(32) NOT NULL,
    artifact_types_json jsonb NOT NULL,
    required_capabilities_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    required_relationships_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    required_resource_families_json jsonb NOT NULL,
    required_facts_json jsonb NOT NULL,
    predicate_json jsonb NOT NULL,
    reason_code character varying(128) NOT NULL,
    remediation text NOT NULL,
    framework_mappings_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    approved_by character varying(255),
    approved_at timestamp with time zone,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    native_kinds_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    scope_resolution character varying(32) DEFAULT 'STATIC'::character varying NOT NULL,
    package_digest character varying(64),
    package_source_ref character varying(1024),
    authored_by character varying(255),
    release_notes text,
    replaces_policy_id character varying(128),
    replaces_version character varying(32),
    parameter_definitions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    control_objective_id character varying(128),
    provider character varying(32),
    evaluation_mode character varying(32),
    evaluation_definition_json jsonb,
    base_evidence_tiers_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    conditional_capabilities_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    certification_parameter_profile_json jsonb,
    release_family character varying(128),
    release_wave character varying(128),
    CONSTRAINT ai_grid_policy_active_digest_check CHECK ((((lifecycle)::text <> ALL ((ARRAY['APPROVED'::character varying, 'CANARY'::character varying, 'PUBLISHED'::character varying, 'DEPRECATED'::character varying])::text[])) OR ((package_digest IS NOT NULL) AND (btrim((package_digest)::text) <> ''::text)) OR (((COALESCE(release_family, ''::character varying))::text <> 'AGCF_PHASE_1'::text) AND (package_source_ref IS NULL)))),
    CONSTRAINT ai_grid_policy_evaluation_mode_check CHECK (((evaluation_mode IS NULL) OR ((evaluation_mode)::text = ANY ((ARRAY['ARTIFACT_FACTS'::character varying, 'DIRECT_RELATIONSHIP'::character varying, 'CORRELATION_PATH'::character varying])::text[])))),
    CONSTRAINT ai_grid_policy_provider_check CHECK (((provider IS NULL) OR ((provider)::text = ANY ((ARRAY['AWS'::character varying, 'AZURE'::character varying, 'MULTI_CLOUD'::character varying])::text[])))),
    CONSTRAINT ai_grid_policy_release_family_check CHECK (((release_family IS NULL) OR (length(TRIM(BOTH FROM release_family)) > 0))),
    CONSTRAINT ai_grid_policy_release_wave_check CHECK (((release_wave IS NULL) OR (length(TRIM(BOTH FROM release_wave)) > 0))),
    CONSTRAINT ai_grid_policy_scope_resolution_check CHECK (((scope_resolution)::text = ANY ((ARRAY['STATIC'::character varying, 'NATIVE_KIND_PLUS_STATIC'::character varying])::text[]))),
    CONSTRAINT ai_grid_policy_versions_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['DRAFT'::character varying, 'VALIDATED'::character varying, 'APPROVED'::character varying, 'CANARY'::character varying, 'PUBLISHED'::character varying, 'RETIRED'::character varying, 'DEPRECATED'::character varying])::text[])))
);


--
-- Name: ai_grid_precision_adjudications; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_precision_adjudications (
    id uuid NOT NULL,
    sample_id uuid NOT NULL,
    final_label character varying(32) NOT NULL,
    rationale text NOT NULL,
    adjudicated_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_precision_adjudications_final_label_check CHECK (((final_label)::text = ANY ((ARRAY['TRUE_POSITIVE'::character varying, 'FALSE_POSITIVE'::character varying, 'TRUE_NEGATIVE'::character varying, 'FALSE_NEGATIVE'::character varying, 'EXCLUDE'::character varying])::text[])))
);


--
-- Name: ai_grid_precision_labels; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_precision_labels (
    id uuid NOT NULL,
    sample_id uuid NOT NULL,
    reviewer character varying(255) NOT NULL,
    label character varying(32) NOT NULL,
    label_version character varying(32) NOT NULL,
    rationale text NOT NULL,
    evidence_reference text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_precision_labels_label_check CHECK (((label)::text = ANY ((ARRAY['TRUE_POSITIVE'::character varying, 'FALSE_POSITIVE'::character varying, 'TRUE_NEGATIVE'::character varying, 'FALSE_NEGATIVE'::character varying, 'EXCLUDE'::character varying])::text[])))
);


--
-- Name: ai_grid_precision_reviews; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_precision_reviews (
    id uuid NOT NULL,
    policy_id character varying(128) NOT NULL,
    policy_version character varying(32) NOT NULL,
    population_definition text NOT NULL,
    sampling_method text NOT NULL,
    minimum_sample_size integer NOT NULL,
    confidence_level double precision NOT NULL,
    precision_threshold double precision DEFAULT 0.95 NOT NULL,
    material_change_digest character varying(128) NOT NULL,
    bias_status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    bias_rationale text,
    bias_reviewed_by character varying(255),
    status character varying(32) DEFAULT 'DRAFT'::character varying NOT NULL,
    resolved_positive_samples integer DEFAULT 0 NOT NULL,
    true_positives integer DEFAULT 0 NOT NULL,
    false_positives integer DEFAULT 0 NOT NULL,
    precision_value double precision,
    confidence_lower double precision,
    confidence_upper double precision,
    finalized_at timestamp with time zone,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    label_set_version character varying(32) DEFAULT 'R1-LEGACY'::character varying NOT NULL,
    answer_key_run_id uuid,
    CONSTRAINT ai_grid_precision_reviews_bias_status_check CHECK (((bias_status)::text = ANY ((ARRAY['PENDING'::character varying, 'PASSED'::character varying, 'FAILED'::character varying])::text[]))),
    CONSTRAINT ai_grid_precision_reviews_confidence_level_check CHECK (((confidence_level > (0)::double precision) AND (confidence_level < (1)::double precision))),
    CONSTRAINT ai_grid_precision_reviews_minimum_sample_size_check CHECK ((minimum_sample_size > 0)),
    CONSTRAINT ai_grid_precision_reviews_precision_threshold_check CHECK (((precision_threshold >= (0)::double precision) AND (precision_threshold <= (1)::double precision))),
    CONSTRAINT ai_grid_precision_reviews_status_check CHECK (((status)::text = ANY ((ARRAY['DRAFT'::character varying, 'IN_REVIEW'::character varying, 'ADJUDICATION'::character varying, 'PASSED'::character varying, 'FAILED'::character varying, 'STALE'::character varying])::text[])))
);


--
-- Name: ai_grid_precision_samples; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_precision_samples (
    id uuid NOT NULL,
    review_id uuid NOT NULL,
    sample_key character varying(160) NOT NULL,
    provider character varying(32) NOT NULL,
    resource_family character varying(128) NOT NULL,
    severity character varying(32) NOT NULL,
    observed_outcome character varying(32) NOT NULL,
    predicted_finding boolean NOT NULL,
    evidence_reference text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_tenant_id uuid,
    source_run_id uuid,
    source_assessment_id uuid,
    source_decision_fingerprint character varying(128),
    provenance_state character varying(32) DEFAULT 'LEGACY_UNBOUND'::character varying NOT NULL,
    CONSTRAINT ai_grid_precision_sample_provenance_state_chk CHECK (((provenance_state)::text = ANY ((ARRAY['PLATFORM_RUN_BOUND'::character varying, 'LEGACY_UNBOUND'::character varying])::text[]))),
    CONSTRAINT ai_grid_precision_samples_observed_outcome_check CHECK (((observed_outcome)::text = ANY ((ARRAY['PASS'::character varying, 'FAIL'::character varying, 'NO_DECISION'::character varying, 'NOT_APPLICABLE'::character varying])::text[]))),
    CONSTRAINT ai_grid_precision_samples_severity_check CHECK (((severity)::text = ANY ((ARRAY['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])))
);


--
-- Name: ai_grid_relationship_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_relationship_definitions (
    relationship_type character varying(128) NOT NULL,
    source character varying(64) NOT NULL,
    directional boolean DEFAULT true NOT NULL,
    lifecycle character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    description text NOT NULL,
    CONSTRAINT ai_grid_relationship_definitions_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['ACTIVE'::character varying, 'RETIRED'::character varying])::text[])))
);


--
-- Name: ai_grid_release_decisions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_release_decisions (
    id uuid NOT NULL,
    release_id character varying(32) NOT NULL,
    decision character varying(16) NOT NULL,
    gate_snapshot_json jsonb NOT NULL,
    reason text NOT NULL,
    decided_by character varying(255) NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_release_decisions_decision_check CHECK (((decision)::text = ANY ((ARRAY['APPROVED'::character varying, 'BLOCKED'::character varying])::text[]))),
    CONSTRAINT ai_grid_release_decisions_release_id_check CHECK (((release_id)::text = ANY ((ARRAY['R0'::character varying, 'R1'::character varying, 'R2'::character varying])::text[])))
);


--
-- Name: ai_grid_release_gate_evidence; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_release_gate_evidence (
    id uuid NOT NULL,
    release_id character varying(32) NOT NULL,
    gate_code character varying(96) NOT NULL,
    status character varying(16) NOT NULL,
    evidence_reference text NOT NULL,
    rationale text NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    recorded_by character varying(255) NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    material_digest character varying(64),
    CONSTRAINT ai_grid_release_gate_evidence_check CHECK ((valid_until > recorded_at)),
    CONSTRAINT ai_grid_release_gate_evidence_release_id_check CHECK (((release_id)::text = ANY ((ARRAY['R0'::character varying, 'R1'::character varying, 'R2'::character varying])::text[]))),
    CONSTRAINT ai_grid_release_gate_evidence_status_check CHECK (((status)::text = ANY ((ARRAY['PASS'::character varying, 'FAIL'::character varying])::text[])))
);


--
-- Name: ai_grid_release_manifest_items; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_release_manifest_items (
    release_id character varying(32) NOT NULL,
    subject_type character varying(32) NOT NULL,
    subject_id character varying(128) NOT NULL,
    subject_version character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_grid_release_manifest_items_subject_type_check CHECK (((subject_type)::text = ANY ((ARRAY['CORRELATION'::character varying, 'POLICY'::character varying])::text[])))
);


--
-- Name: ai_grid_resource_family_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_resource_family_definitions (
    resource_family character varying(128) NOT NULL,
    provider character varying(32) NOT NULL,
    scope_semantics character varying(32) NOT NULL,
    lifecycle character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL,
    description text NOT NULL,
    CONSTRAINT ai_grid_resource_family_definitions_lifecycle_check CHECK (((lifecycle)::text = ANY ((ARRAY['ACTIVE'::character varying, 'RETIRED'::character varying])::text[]))),
    CONSTRAINT ai_grid_resource_family_definitions_provider_check CHECK (((provider)::text = ANY ((ARRAY['AWS'::character varying, 'AZURE'::character varying, 'MULTI_CLOUD'::character varying])::text[]))),
    CONSTRAINT ai_grid_resource_family_definitions_scope_semantics_check CHECK (((scope_semantics)::text = ANY ((ARRAY['REGIONAL'::character varying, 'ACCOUNT_GLOBAL'::character varying])::text[])))
);


--
-- Name: ai_grid_technology_versions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_technology_versions (
    technology_id character varying(128) NOT NULL,
    version character varying(32) NOT NULL,
    display_name character varying(255) NOT NULL,
    provider character varying(32) NOT NULL,
    lifecycle character varying(32) NOT NULL,
    aliases_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    resource_families_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_grid_test_data_reset_log; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.ai_grid_test_data_reset_log (
    id boolean DEFAULT true NOT NULL,
    reset_by character varying(255) NOT NULL,
    reset_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_count integer NOT NULL,
    confirmation_digest character varying(64) NOT NULL,
    CONSTRAINT ai_grid_test_data_reset_log_id_check CHECK (id)
);


--
-- Name: app_user_global_roles; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.app_user_global_roles (
    id uuid NOT NULL,
    app_user_id uuid NOT NULL,
    role character varying(64) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: app_users; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.app_users (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    display_name character varying(255),
    email character varying(255),
    external_subject character varying(255) NOT NULL,
    last_seen_at timestamp with time zone,
    password_hash character varying(255),
    password_set_at timestamp with time zone,
    password_setup_token_expires_at timestamp with time zone,
    password_setup_token_hash character varying(255),
    platform_owner boolean NOT NULL,
    status character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: cpe_dim; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.cpe_dim (
    id uuid NOT NULL,
    raw_cpe character varying(1200) NOT NULL,
    normalized_cpe character varying(1200) NOT NULL,
    part character varying(500) NOT NULL,
    vendor character varying(500) NOT NULL,
    product character varying(500) NOT NULL,
    version character varying(500),
    update character varying(500),
    edition character varying(500),
    language character varying(500),
    sw_edition character varying(500),
    target_sw character varying(500),
    target_hw character varying(500),
    other character varying(500),
    cpe_key character varying(1000) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: entitlement_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.entitlement_definitions (
    key character varying(128) NOT NULL,
    category character varying(64) NOT NULL,
    value_type character varying(32) NOT NULL,
    description character varying(500),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: eol_product_catalog; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.eol_product_catalog (
    id bigint NOT NULL,
    slug character varying(200) NOT NULL,
    cpe_vendor character varying(200),
    cpe_product character varying(200),
    purl_type character varying(100),
    purl_namespace character varying(200),
    display_name character varying(200),
    aliases text,
    last_modified character varying(50),
    last_fetched_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: eol_product_catalog_id_seq; Type: SEQUENCE; Schema: platform; Owner: -
--

ALTER TABLE platform.eol_product_catalog ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME platform.eol_product_catalog_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: eol_release; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.eol_release (
    id bigint NOT NULL,
    product_slug character varying(200) NOT NULL,
    cycle character varying(100) NOT NULL,
    release_date date,
    eol_date date,
    eol_boolean boolean,
    support_end_date date,
    extended_support_date date,
    latest_version character varying(100),
    latest_release_date date,
    is_lts boolean NOT NULL,
    is_eol boolean NOT NULL,
    is_eoas boolean,
    is_eoes boolean,
    security_support_date date,
    official_source_url character varying(500),
    support_phase character varying(30),
    discontinued boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: eol_release_id_seq; Type: SEQUENCE; Schema: platform; Owner: -
--

ALTER TABLE platform.eol_release ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME platform.eol_release_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: finding_queue_preferences; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.finding_queue_preferences (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    default_queue_ref character varying(160) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: TABLE finding_queue_preferences; Type: COMMENT; Schema: platform; Owner: -
--

COMMENT ON TABLE platform.finding_queue_preferences IS 'Per-user default finding queue selection';


--
-- Name: identity_links; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.identity_links (
    id uuid NOT NULL,
    confidence double precision,
    created_at timestamp with time zone NOT NULL,
    from_identifier_id uuid,
    last_seen_at timestamp with time zone,
    link_type character varying(80) NOT NULL,
    match_rule character varying(40),
    provenance_note character varying(500),
    source character varying(80) NOT NULL,
    source_id character varying(255),
    source_type character varying(80),
    target_id character varying(255),
    target_type character varying(80),
    to_identifier_id uuid,
    updated_at timestamp with time zone NOT NULL,
    verified boolean NOT NULL,
    verified_at timestamp with time zone,
    verified_by character varying(255)
);


--
-- Name: personal_finding_queues; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.personal_finding_queues (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    queue_key character varying(120) NOT NULL,
    title character varying(160) NOT NULL,
    description character varying(500),
    filter_json text NOT NULL,
    display_order integer NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: TABLE personal_finding_queues; Type: COMMENT; Schema: platform; Owner: -
--

COMMENT ON TABLE platform.personal_finding_queues IS 'Personal finding queue definitions per tenant user';


--
-- Name: plan_definitions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.plan_definitions (
    code character varying(64) NOT NULL,
    display_name character varying(120) NOT NULL,
    status character varying(32) NOT NULL,
    description character varying(500),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: plan_entitlements; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.plan_entitlements (
    plan_code character varying(64) NOT NULL,
    entitlement_key character varying(128) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: software_eol_mapping; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.software_eol_mapping (
    id bigint NOT NULL,
    software_identity_id uuid,
    normalized_key character varying(500) NOT NULL,
    eol_slug character varying(200),
    match_confidence character varying(20),
    match_method character varying(50),
    confirmed boolean NOT NULL,
    confirmed_by character varying(200),
    confirmed_at timestamp with time zone,
    previous_slug character varying(200),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: software_eol_mapping_id_seq; Type: SEQUENCE; Schema: platform; Owner: -
--

ALTER TABLE platform.software_eol_mapping ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME platform.software_eol_mapping_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: software_identifiers; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.software_identifiers (
    id uuid NOT NULL,
    confidence double precision,
    created_at timestamp with time zone NOT NULL,
    id_type character varying(40) NOT NULL,
    normalized_value character varying(1000) NOT NULL,
    provenance_note character varying(500),
    raw_value character varying(1000),
    source character varying(80) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    verified boolean NOT NULL,
    software_identity_id uuid NOT NULL
);


--
-- Name: software_identities; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.software_identities (
    id uuid NOT NULL,
    canonical_key character varying(400) NOT NULL,
    display_name character varying(300) NOT NULL,
    vendor character varying(255),
    product character varying(255),
    product_hash character varying(255),
    purl character varying(1200),
    cpe23 character varying(1200),
    vendor_product_id character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: sync_runs; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.sync_runs (
    id uuid NOT NULL,
    completed_at timestamp with time zone,
    error_message character varying(2000),
    metadata_json text,
    records_failed integer NOT NULL,
    records_fetched integer NOT NULL,
    records_inserted integer NOT NULL,
    records_updated integer NOT NULL,
    run_scope character varying(64) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    status character varying(255) NOT NULL,
    sync_type character varying(255) NOT NULL,
    tenant_id uuid
);


--
-- Name: tenant_entitlement_overrides; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenant_entitlement_overrides (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    entitlement_key character varying(128) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    reason character varying(500),
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: tenant_memberships; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenant_memberships (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    role character varying(255) NOT NULL,
    status character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    invited_by uuid,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provenance character varying(32) DEFAULT 'MANUAL'::character varying NOT NULL
);


--
-- Name: tenant_schema_versions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenant_schema_versions (
    tenant_id uuid NOT NULL,
    schema_name character varying(120) NOT NULL,
    current_version integer DEFAULT 0 NOT NULL,
    target_version integer NOT NULL,
    status character varying(24) DEFAULT 'PENDING'::character varying NOT NULL,
    structural_checksum character varying(64),
    migration_started_at timestamp with time zone,
    migration_completed_at timestamp with time zone,
    last_successful_version integer DEFAULT 0 NOT NULL,
    failure_code character varying(80),
    failure_message character varying(1000),
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    migration_run_id uuid,
    CONSTRAINT tenant_schema_versions_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'MIGRATING'::character varying, 'CURRENT'::character varying, 'FAILED'::character varying, 'DRIFTED'::character varying, 'PROVISIONING_FAILED'::character varying])::text[])))
);


--
-- Name: TABLE tenant_schema_versions; Type: COMMENT; Schema: platform; Owner: -
--

COMMENT ON TABLE platform.tenant_schema_versions IS 'Operational projection of per-schema tenant_schema_history. Flyway history remains authoritative.';


--
-- Name: tenant_support_grants; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenant_support_grants (
    id uuid NOT NULL,
    accepted_at timestamp with time zone,
    access_mode character varying(255) NOT NULL,
    expires_at timestamp with time zone,
    invited_platform_subject character varying(255) NOT NULL,
    reason character varying(255) NOT NULL,
    requested_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    scope character varying(255),
    status character varying(255) NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    accepted_by uuid,
    granted_by uuid NOT NULL,
    revoked_by uuid,
    tenant_id uuid NOT NULL
);


--
-- Name: tenant_user_invites; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenant_user_invites (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    invited_by uuid,
    email character varying(320) NOT NULL,
    display_name character varying(255),
    external_subject character varying(320) NOT NULL,
    role character varying(64) NOT NULL,
    status character varying(32) NOT NULL,
    token character varying(96) NOT NULL,
    provider_message_id character varying(255),
    delivery_detail character varying(500),
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    last_sent_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: tenants; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.tenants (
    id uuid NOT NULL,
    billing_ref character varying(255),
    created_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone,
    demo_created_by character varying(255),
    demo_expires_at timestamp with time zone,
    demo_owner_email character varying(255),
    demo_source character varying(255),
    expired_at timestamp with time zone,
    max_connector_count integer NOT NULL,
    max_daily_exposure_refreshes integer NOT NULL,
    max_daily_sbom_uploads integer NOT NULL,
    max_export_rows integer NOT NULL,
    max_service_account_count integer NOT NULL,
    name character varying(255) NOT NULL,
    plan_code character varying(255) NOT NULL,
    purge_error character varying(2000),
    purge_started_at timestamp with time zone,
    purge_status character varying(255),
    purged_at timestamp with time zone,
    schema_name character varying(255) NOT NULL,
    slug character varying(255),
    status character varying(255) NOT NULL,
    suspended_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL,
    sbom_rate_limit_window_seconds integer,
    max_sbom_jobs_per_rate_limit_window integer,
    max_active_sbom_jobs integer
);


-- Canonical non-customer workspace required by application startup and CI fixtures.
INSERT INTO platform.tenants (
    id, name, slug, schema_name, status, plan_code, created_at, updated_at,
    max_connector_count, max_service_account_count, max_daily_sbom_uploads,
    max_export_rows, max_daily_exposure_refreshes
)
VALUES (
    'e5fe0d29-1d64-4175-8ce6-c34f42b214cc', 'Default Workspace', 'default-workspace',
    'tenant_default', 'ACTIVE', 'ENTERPRISE', now(), now(), 10, 25, 100, 50000, 25
);


--
-- Name: vex_assertions; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vex_assertions (
    id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    observation_id uuid,
    target_id uuid NOT NULL,
    software_identity_id uuid,
    cpe_id uuid,
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
    published_at timestamp with time zone,
    last_seen_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: vulnerabilities; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerabilities (
    id uuid NOT NULL,
    external_id character varying(50) NOT NULL,
    source character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    description_snippet character varying(500),
    description_archive_key character varying(200),
    cvss_score double precision,
    severity character varying(20) NOT NULL,
    epss_score double precision,
    in_kev boolean NOT NULL,
    cvss_vector character varying(300),
    cvss_version character varying(20),
    attack_vector character varying(20),
    attack_complexity character varying(20),
    privileges_required character varying(20),
    user_interaction character varying(20),
    cvss_scope character varying(20),
    exploitability_score double precision,
    impact_score double precision,
    cwe_ids character varying(200),
    source_identifier character varying(255),
    vuln_status character varying(80),
    kev_date_added date,
    kev_due_date date,
    kev_required_action character varying(2000),
    references_json text,
    raw_payload_archive_key character varying(200),
    published_at timestamp with time zone,
    last_modified_at timestamp with time zone,
    epss_updated_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: vulnerability_config_expr; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_config_expr (
    id uuid NOT NULL,
    child_node_count integer,
    config_index integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expr_json text,
    match_criteria_count integer,
    negate boolean NOT NULL,
    node_path character varying(1000) NOT NULL,
    operator character varying(32),
    parent_path character varying(1000),
    source character varying(40) NOT NULL,
    vulnerability_id uuid NOT NULL
);


--
-- Name: vulnerability_intel_observations; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_intel_observations (
    id uuid NOT NULL,
    vulnerability_id uuid,
    source_system character varying(80) NOT NULL,
    source_record_id character varying(255) NOT NULL,
    source_url character varying(1200),
    title character varying(255),
    description text,
    severity character varying(40),
    cvss_score double precision,
    cvss_vector character varying(300),
    epss_score double precision,
    in_kev boolean,
    vuln_status character varying(120),
    cwe_ids character varying(2000),
    references_json text,
    source_identifier character varying(255),
    published_at timestamp with time zone,
    last_modified_at timestamp with time zone,
    raw_payload text,
    payload_hash character varying(128),
    observed_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: vulnerability_intel_relations; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_intel_relations (
    id uuid NOT NULL,
    confidence double precision,
    created_at timestamp with time zone NOT NULL,
    from_observation_id uuid NOT NULL,
    provenance_note character varying(500),
    relation_type character varying(80) NOT NULL,
    source_system character varying(80) NOT NULL,
    to_observation_id uuid NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    verified boolean NOT NULL
);


--
-- Name: vulnerability_intel_summary; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_intel_summary (
    id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    external_id character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    description_snippet character varying(220),
    severity character varying(255) NOT NULL,
    cvss_score double precision,
    epss_score double precision,
    in_kev boolean NOT NULL,
    vuln_status character varying(255),
    source_count integer NOT NULL,
    published_at timestamp with time zone,
    last_modified_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    summary_updated_at timestamp with time zone NOT NULL
);


--
-- Name: vulnerability_intel_summary_sources; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_intel_summary_sources (
    id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    source_system character varying(80) NOT NULL
);


--
-- Name: vulnerability_rules; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_rules (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    cpe character varying(255),
    cpe_product character varying(255),
    cpe_vendor character varying(255),
    ecosystem character varying(255) NOT NULL,
    package_name character varying(255) NOT NULL,
    version_exact character varying(255),
    version_start character varying(255),
    version_start_inclusive boolean,
    version_end character varying(255),
    version_end_inclusive boolean,
    vulnerability_id uuid NOT NULL
);


--
-- Name: vulnerability_targets; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.vulnerability_targets (
    id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    software_identity_id uuid,
    target_type character varying(40) NOT NULL,
    raw_target character varying(1200),
    normalized_target_key character varying(500) NOT NULL,
    ecosystem character varying(120),
    namespace character varying(120),
    package_name character varying(220),
    repo_url character varying(1200),
    version_exact character varying(255),
    version_start character varying(255),
    start_inclusive boolean,
    version_end character varying(255),
    end_inclusive boolean,
    introduced character varying(255),
    fixed character varying(255),
    version_scheme character varying(40) NOT NULL,
    constraint_type character varying(40),
    cpe character varying(1200),
    cpe_wildcard_score integer,
    cpe_id uuid,
    qualifier_part character varying(40),
    qualifier_vendor character varying(255),
    qualifier_product character varying(255),
    qualifier_version character varying(255),
    qualifier_update character varying(255),
    qualifier_edition character varying(255),
    qualifier_language character varying(255),
    qualifier_sw_edition character varying(255),
    qualifier_target_sw character varying(255),
    qualifier_target_hw character varying(255),
    qualifier_other character varying(255),
    qualifiers_json text,
    source character varying(80) NOT NULL,
    kb_version character varying(120),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: finding_list_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_list_projection (
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
    first_observed_at timestamp with time zone
);


--
-- Name: finding_workspace_projection_status; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_workspace_projection_status (
    projection_key character varying(64) NOT NULL,
    last_computed_at timestamp with time zone NOT NULL,
    finding_count bigint NOT NULL,
    source_finding_count bigint DEFAULT 0 NOT NULL,
    last_rebuild_duration_ms bigint
);


--
-- Name: ai_grid_answer_key_cases ai_grid_answer_key_cases_environment_id_case_key_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_cases
    ADD CONSTRAINT ai_grid_answer_key_cases_environment_id_case_key_key UNIQUE (environment_id, case_key);


--
-- Name: ai_grid_answer_key_cases ai_grid_answer_key_cases_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_cases
    ADD CONSTRAINT ai_grid_answer_key_cases_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_answer_key_environments ai_grid_answer_key_environments_environment_key_version_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_environments
    ADD CONSTRAINT ai_grid_answer_key_environments_environment_key_version_key UNIQUE (environment_key, version);


--
-- Name: ai_grid_answer_key_environments ai_grid_answer_key_environments_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_environments
    ADD CONSTRAINT ai_grid_answer_key_environments_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_answer_key_results ai_grid_answer_key_results_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_results
    ADD CONSTRAINT ai_grid_answer_key_results_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_answer_key_results ai_grid_answer_key_results_run_id_case_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_results
    ADD CONSTRAINT ai_grid_answer_key_results_run_id_case_id_key UNIQUE (run_id, case_id);


--
-- Name: ai_grid_answer_key_runs ai_grid_answer_key_runs_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_runs
    ADD CONSTRAINT ai_grid_answer_key_runs_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_capability_definitions ai_grid_capability_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_capability_definitions
    ADD CONSTRAINT ai_grid_capability_definitions_pkey PRIMARY KEY (capability_id);


--
-- Name: ai_grid_control_objectives ai_grid_control_objectives_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_control_objectives
    ADD CONSTRAINT ai_grid_control_objectives_pkey PRIMARY KEY (control_objective_id);


--
-- Name: ai_grid_correlation_precision_reviews ai_grid_correlation_precision_correlation_id_correlation_ve_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_correlation_precision_reviews
    ADD CONSTRAINT ai_grid_correlation_precision_correlation_id_correlation_ve_key UNIQUE (correlation_id, correlation_version, material_digest);


--
-- Name: ai_grid_correlation_precision_reviews ai_grid_correlation_precision_reviews_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_correlation_precision_reviews
    ADD CONSTRAINT ai_grid_correlation_precision_reviews_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_correlation_versions ai_grid_correlation_versions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_correlation_versions
    ADD CONSTRAINT ai_grid_correlation_versions_pkey PRIMARY KEY (correlation_id, version);


--
-- Name: ai_grid_fact_definitions ai_grid_fact_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_fact_definitions
    ADD CONSTRAINT ai_grid_fact_definitions_pkey PRIMARY KEY (fact_key, version);


--
-- Name: ai_grid_phase_1_preview_gate_evidence ai_grid_phase_1_preview_gate_evidence_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_phase_1_preview_gate_evidence
    ADD CONSTRAINT ai_grid_phase_1_preview_gate_evidence_pkey PRIMARY KEY (gate_key);


--
-- Name: ai_grid_phase_1_preview_release ai_grid_phase_1_preview_release_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_phase_1_preview_release
    ADD CONSTRAINT ai_grid_phase_1_preview_release_pkey PRIMARY KEY (release_family);


--
-- Name: ai_grid_phase_1_release_gate_evidence ai_grid_phase_1_release_gate_evidence_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_phase_1_release_gate_evidence
    ADD CONSTRAINT ai_grid_phase_1_release_gate_evidence_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_phase_1_tenant_migration_audit ai_grid_phase_1_tenant_migration_audit_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_phase_1_tenant_migration_audit
    ADD CONSTRAINT ai_grid_phase_1_tenant_migration_audit_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_candidates ai_grid_policy_candidates_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_candidates
    ADD CONSTRAINT ai_grid_policy_candidates_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_deprecation_tasks ai_grid_policy_deprecation_tasks_deprecation_id_tenant_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecation_tasks
    ADD CONSTRAINT ai_grid_policy_deprecation_tasks_deprecation_id_tenant_id_key UNIQUE (deprecation_id, tenant_id);


--
-- Name: ai_grid_policy_deprecation_tasks ai_grid_policy_deprecation_tasks_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecation_tasks
    ADD CONSTRAINT ai_grid_policy_deprecation_tasks_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_deprecations ai_grid_policy_deprecations_idempotency_key_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecations
    ADD CONSTRAINT ai_grid_policy_deprecations_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: ai_grid_policy_deprecations ai_grid_policy_deprecations_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecations
    ADD CONSTRAINT ai_grid_policy_deprecations_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_deprecations ai_grid_policy_deprecations_policy_id_policy_version_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecations
    ADD CONSTRAINT ai_grid_policy_deprecations_policy_id_policy_version_key UNIQUE (policy_id, policy_version);


--
-- Name: ai_grid_policy_dev_deployments ai_grid_policy_dev_deployments_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_dev_deployments
    ADD CONSTRAINT ai_grid_policy_dev_deployments_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_distribution ai_grid_policy_distribution_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_distribution
    ADD CONSTRAINT ai_grid_policy_distribution_pkey PRIMARY KEY (policy_id);


--
-- Name: ai_grid_policy_inactivation_tasks ai_grid_policy_inactivation_tasks_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_inactivation_tasks
    ADD CONSTRAINT ai_grid_policy_inactivation_tasks_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_inactivation_tasks ai_grid_policy_inactivation_tasks_policy_id_tenant_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_inactivation_tasks
    ADD CONSTRAINT ai_grid_policy_inactivation_tasks_policy_id_tenant_id_key UNIQUE (policy_id, tenant_id);


--
-- Name: ai_grid_policy_migration_ledger ai_grid_policy_migration_ledger_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_migration_ledger
    ADD CONSTRAINT ai_grid_policy_migration_ledger_pkey PRIMARY KEY (legacy_detector_id);


--
-- Name: ai_grid_policy_release_bindings ai_grid_policy_release_bindin_policy_id_policy_version_appr_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_bindings
    ADD CONSTRAINT ai_grid_policy_release_bindin_policy_id_policy_version_appr_key UNIQUE (policy_id, policy_version, approved_package_digest);


--
-- Name: ai_grid_policy_release_bindings ai_grid_policy_release_bindings_approval_decision_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_bindings
    ADD CONSTRAINT ai_grid_policy_release_bindings_approval_decision_id_key UNIQUE (approval_decision_id);


--
-- Name: ai_grid_policy_release_bindings ai_grid_policy_release_bindings_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_bindings
    ADD CONSTRAINT ai_grid_policy_release_bindings_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_release_decisions ai_grid_policy_release_decisions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_decisions
    ADD CONSTRAINT ai_grid_policy_release_decisions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_replacements ai_grid_policy_replacements_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_replacements
    ADD CONSTRAINT ai_grid_policy_replacements_pkey PRIMARY KEY (predecessor_policy_id);


--
-- Name: ai_grid_policy_replacements ai_grid_policy_replacements_successor_policy_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_replacements
    ADD CONSTRAINT ai_grid_policy_replacements_successor_policy_id_key UNIQUE (successor_policy_id);


--
-- Name: ai_grid_policy_rollout_tasks ai_grid_policy_rollout_tasks_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_rollout_tasks ai_grid_policy_rollout_tasks_rollout_id_tenant_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_rollout_id_tenant_id_key UNIQUE (rollout_id, tenant_id);


--
-- Name: ai_grid_policy_rollouts ai_grid_policy_rollouts_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollouts
    ADD CONSTRAINT ai_grid_policy_rollouts_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_policy_rollouts ai_grid_policy_rollouts_release_id_policy_id_new_version_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollouts
    ADD CONSTRAINT ai_grid_policy_rollouts_release_id_policy_id_new_version_key UNIQUE (release_id, policy_id, new_version);


--
-- Name: ai_grid_policy_versions ai_grid_policy_versions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_versions_pkey PRIMARY KEY (policy_id, version);


--
-- Name: ai_grid_precision_adjudications ai_grid_precision_adjudications_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_adjudications
    ADD CONSTRAINT ai_grid_precision_adjudications_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_precision_adjudications ai_grid_precision_adjudications_sample_id_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_adjudications
    ADD CONSTRAINT ai_grid_precision_adjudications_sample_id_key UNIQUE (sample_id);


--
-- Name: ai_grid_precision_labels ai_grid_precision_labels_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_labels
    ADD CONSTRAINT ai_grid_precision_labels_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_precision_labels ai_grid_precision_labels_sample_id_reviewer_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_labels
    ADD CONSTRAINT ai_grid_precision_labels_sample_id_reviewer_key UNIQUE (sample_id, reviewer);


--
-- Name: ai_grid_precision_reviews ai_grid_precision_reviews_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_reviews
    ADD CONSTRAINT ai_grid_precision_reviews_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_precision_reviews ai_grid_precision_reviews_policy_id_policy_version_material_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_reviews
    ADD CONSTRAINT ai_grid_precision_reviews_policy_id_policy_version_material_key UNIQUE (policy_id, policy_version, material_change_digest);


--
-- Name: ai_grid_precision_samples ai_grid_precision_samples_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_samples_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_precision_samples ai_grid_precision_samples_review_id_sample_key_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_samples_review_id_sample_key_key UNIQUE (review_id, sample_key);


--
-- Name: ai_grid_relationship_definitions ai_grid_relationship_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_relationship_definitions
    ADD CONSTRAINT ai_grid_relationship_definitions_pkey PRIMARY KEY (relationship_type);


--
-- Name: ai_grid_release_decisions ai_grid_release_decisions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_release_decisions
    ADD CONSTRAINT ai_grid_release_decisions_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_release_gate_evidence ai_grid_release_gate_evidence_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_release_gate_evidence
    ADD CONSTRAINT ai_grid_release_gate_evidence_pkey PRIMARY KEY (id);


--
-- Name: ai_grid_release_manifest_items ai_grid_release_manifest_items_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_release_manifest_items
    ADD CONSTRAINT ai_grid_release_manifest_items_pkey PRIMARY KEY (release_id, subject_type, subject_id, subject_version);


--
-- Name: ai_grid_resource_family_definitions ai_grid_resource_family_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_resource_family_definitions
    ADD CONSTRAINT ai_grid_resource_family_definitions_pkey PRIMARY KEY (resource_family);


--
-- Name: ai_grid_technology_versions ai_grid_technology_versions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_technology_versions
    ADD CONSTRAINT ai_grid_technology_versions_pkey PRIMARY KEY (technology_id, version);


--
-- Name: ai_grid_test_data_reset_log ai_grid_test_data_reset_log_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_test_data_reset_log
    ADD CONSTRAINT ai_grid_test_data_reset_log_pkey PRIMARY KEY (id);


--
-- Name: app_user_global_roles app_user_global_roles_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.app_user_global_roles
    ADD CONSTRAINT app_user_global_roles_pkey PRIMARY KEY (id);


--
-- Name: app_users app_users_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.app_users
    ADD CONSTRAINT app_users_pkey PRIMARY KEY (id);


--
-- Name: cpe_dim cpe_dim_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.cpe_dim
    ADD CONSTRAINT cpe_dim_pkey PRIMARY KEY (id);


--
-- Name: entitlement_definitions entitlement_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.entitlement_definitions
    ADD CONSTRAINT entitlement_definitions_pkey PRIMARY KEY (key);


--
-- Name: eol_product_catalog eol_product_catalog_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.eol_product_catalog
    ADD CONSTRAINT eol_product_catalog_pkey PRIMARY KEY (id);


--
-- Name: eol_release eol_release_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.eol_release
    ADD CONSTRAINT eol_release_pkey PRIMARY KEY (id);


--
-- Name: finding_queue_preferences finding_queue_preferences_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.finding_queue_preferences
    ADD CONSTRAINT finding_queue_preferences_pkey PRIMARY KEY (id);


--
-- Name: identity_links identity_links_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.identity_links
    ADD CONSTRAINT identity_links_pkey PRIMARY KEY (id);


--
-- Name: personal_finding_queues personal_finding_queues_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.personal_finding_queues
    ADD CONSTRAINT personal_finding_queues_pkey PRIMARY KEY (id);


--
-- Name: plan_entitlements pk_plan_entitlements; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.plan_entitlements
    ADD CONSTRAINT pk_plan_entitlements PRIMARY KEY (plan_code, entitlement_key);


--
-- Name: plan_definitions plan_definitions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.plan_definitions
    ADD CONSTRAINT plan_definitions_pkey PRIMARY KEY (code);


--
-- Name: software_eol_mapping software_eol_mapping_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_eol_mapping
    ADD CONSTRAINT software_eol_mapping_pkey PRIMARY KEY (id);


--
-- Name: software_identifiers software_identifiers_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_identifiers
    ADD CONSTRAINT software_identifiers_pkey PRIMARY KEY (id);


--
-- Name: software_identities software_identities_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_identities
    ADD CONSTRAINT software_identities_pkey PRIMARY KEY (id);


--
-- Name: sync_runs sync_runs_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.sync_runs
    ADD CONSTRAINT sync_runs_pkey PRIMARY KEY (id);


--
-- Name: tenant_entitlement_overrides tenant_entitlement_overrides_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_entitlement_overrides
    ADD CONSTRAINT tenant_entitlement_overrides_pkey PRIMARY KEY (id);


--
-- Name: tenant_memberships tenant_memberships_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_memberships
    ADD CONSTRAINT tenant_memberships_pkey PRIMARY KEY (id);


--
-- Name: tenant_schema_versions tenant_schema_versions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_schema_versions
    ADD CONSTRAINT tenant_schema_versions_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_schema_versions tenant_schema_versions_schema_name_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_schema_versions
    ADD CONSTRAINT tenant_schema_versions_schema_name_key UNIQUE (schema_name);


--
-- Name: tenant_support_grants tenant_support_grants_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_support_grants
    ADD CONSTRAINT tenant_support_grants_pkey PRIMARY KEY (id);


--
-- Name: tenant_user_invites tenant_user_invites_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_user_invites
    ADD CONSTRAINT tenant_user_invites_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: app_user_global_roles uk_app_user_global_roles_user_role; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.app_user_global_roles
    ADD CONSTRAINT uk_app_user_global_roles_user_role UNIQUE (app_user_id, role);


--
-- Name: app_users uk_app_users_external_subject; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.app_users
    ADD CONSTRAINT uk_app_users_external_subject UNIQUE (external_subject);


--
-- Name: cpe_dim uk_cpe_dim_normalized; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.cpe_dim
    ADD CONSTRAINT uk_cpe_dim_normalized UNIQUE (normalized_cpe);


--
-- Name: eol_product_catalog uk_eol_product_catalog_slug; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.eol_product_catalog
    ADD CONSTRAINT uk_eol_product_catalog_slug UNIQUE (slug);


--
-- Name: eol_release uk_eol_release_slug_cycle; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.eol_release
    ADD CONSTRAINT uk_eol_release_slug_cycle UNIQUE (product_slug, cycle);


--
-- Name: finding_queue_preferences uk_finding_queue_preferences_owner; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.finding_queue_preferences
    ADD CONSTRAINT uk_finding_queue_preferences_owner UNIQUE (tenant_id, owner_user_id);


--
-- Name: identity_links uk_identity_links_pair_type_source; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.identity_links
    ADD CONSTRAINT uk_identity_links_pair_type_source UNIQUE (from_identifier_id, to_identifier_id, link_type, source);


--
-- Name: personal_finding_queues uk_personal_finding_queues_owner_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.personal_finding_queues
    ADD CONSTRAINT uk_personal_finding_queues_owner_key UNIQUE (tenant_id, owner_user_id, queue_key);


--
-- Name: personal_finding_queues uk_personal_finding_queues_owner_title; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.personal_finding_queues
    ADD CONSTRAINT uk_personal_finding_queues_owner_title UNIQUE (tenant_id, owner_user_id, title);


--
-- Name: software_eol_mapping uk_software_eol_mapping_normalized_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_eol_mapping
    ADD CONSTRAINT uk_software_eol_mapping_normalized_key UNIQUE (normalized_key);


--
-- Name: software_identifiers uk_software_identifier_identity_type_value; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_identifiers
    ADD CONSTRAINT uk_software_identifier_identity_type_value UNIQUE (software_identity_id, id_type, normalized_value);


--
-- Name: software_identities uk_software_identities_canonical_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_identities
    ADD CONSTRAINT uk_software_identities_canonical_key UNIQUE (canonical_key);


--
-- Name: tenant_entitlement_overrides uk_tenant_entitlement_overrides_tenant_key; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_entitlement_overrides
    ADD CONSTRAINT uk_tenant_entitlement_overrides_tenant_key UNIQUE (tenant_id, entitlement_key);


--
-- Name: tenant_user_invites uk_tenant_user_invites_token; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_user_invites
    ADD CONSTRAINT uk_tenant_user_invites_token UNIQUE (token);


--
-- Name: tenants uk_tenants_name; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenants
    ADD CONSTRAINT uk_tenants_name UNIQUE (name);


--
-- Name: tenants uk_tenants_schema_name; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenants
    ADD CONSTRAINT uk_tenants_schema_name UNIQUE (schema_name);


--
-- Name: tenants uk_tenants_slug; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenants
    ADD CONSTRAINT uk_tenants_slug UNIQUE (slug);


--
-- Name: vex_assertions uk_vex_assertions_statement; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT uk_vex_assertions_statement UNIQUE (vulnerability_id, source_system, document_id, statement_key);


--
-- Name: vex_assertions uk_vex_assertions_target; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT uk_vex_assertions_target UNIQUE (target_id);


--
-- Name: vulnerability_intel_summary_sources uk_vintel_summary_source_vuln_source; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_summary_sources
    ADD CONSTRAINT uk_vintel_summary_source_vuln_source UNIQUE (vulnerability_id, source_system);


--
-- Name: vulnerability_intel_observations uk_vuln_intel_observation_source_record; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_observations
    ADD CONSTRAINT uk_vuln_intel_observation_source_record UNIQUE (source_system, source_record_id);


--
-- Name: vulnerability_intel_relations uk_vuln_intel_relations_pair_type_source; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_relations
    ADD CONSTRAINT uk_vuln_intel_relations_pair_type_source UNIQUE (from_observation_id, to_observation_id, relation_type, source_system);


--
-- Name: vulnerabilities uk_vulnerabilities_external_id; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerabilities
    ADD CONSTRAINT uk_vulnerabilities_external_id UNIQUE (external_id);


--
-- Name: vulnerability_intel_summary uk_vulnerability_intel_summary_vulnerability; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_summary
    ADD CONSTRAINT uk_vulnerability_intel_summary_vulnerability UNIQUE (vulnerability_id);


--
-- Name: vex_assertions vex_assertions_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT vex_assertions_pkey PRIMARY KEY (id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_config_expr vulnerability_config_expr_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_config_expr
    ADD CONSTRAINT vulnerability_config_expr_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_intel_observations vulnerability_intel_observations_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_observations
    ADD CONSTRAINT vulnerability_intel_observations_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_intel_relations vulnerability_intel_relations_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_relations
    ADD CONSTRAINT vulnerability_intel_relations_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_intel_summary vulnerability_intel_summary_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_summary
    ADD CONSTRAINT vulnerability_intel_summary_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_intel_summary_sources vulnerability_intel_summary_sources_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_summary_sources
    ADD CONSTRAINT vulnerability_intel_summary_sources_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_rules vulnerability_rules_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_rules
    ADD CONSTRAINT vulnerability_rules_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_targets vulnerability_targets_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_targets
    ADD CONSTRAINT vulnerability_targets_pkey PRIMARY KEY (id);


--
-- Name: finding_list_projection finding_list_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_list_projection
    ADD CONSTRAINT finding_list_projection_pkey PRIMARY KEY (finding_id);


--
-- Name: finding_workspace_projection_status finding_workspace_projection_status_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_workspace_projection_status
    ADD CONSTRAINT finding_workspace_projection_status_pkey PRIMARY KEY (projection_key);


--
-- Name: idx_ai_grid_answer_key_run_environment; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_answer_key_run_environment ON platform.ai_grid_answer_key_runs USING btree (environment_id, completed_at DESC);


--
-- Name: idx_ai_grid_answer_key_run_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_answer_key_run_source ON platform.ai_grid_answer_key_runs USING btree (source_tenant_id, source_run_id, completed_at DESC);


--
-- Name: idx_ai_grid_dev_deployments_policy; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_dev_deployments_policy ON platform.ai_grid_policy_dev_deployments USING btree (policy_id, deployed_at DESC);


--
-- Name: idx_ai_grid_phase_1_migration_audit_tenant; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_phase_1_migration_audit_tenant ON platform.ai_grid_phase_1_tenant_migration_audit USING btree (tenant_id, applied_at DESC);


--
-- Name: idx_ai_grid_phase_1_release_gate_latest; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_phase_1_release_gate_latest ON platform.ai_grid_phase_1_release_gate_evidence USING btree (gate_key, recorded_at DESC);


--
-- Name: idx_ai_grid_policy_deprecation_tasks_claim; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_policy_deprecation_tasks_claim ON platform.ai_grid_policy_deprecation_tasks USING btree (state, next_retry_at, created_at);


--
-- Name: idx_ai_grid_policy_inactivation_claim; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_policy_inactivation_claim ON platform.ai_grid_policy_inactivation_tasks USING btree (status, next_retry_at, queued_at);


--
-- Name: idx_ai_grid_policy_release_bindings_active; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_policy_release_bindings_active ON platform.ai_grid_policy_release_bindings USING btree (policy_id, policy_version) WHERE ((state)::text = 'ACTIVE'::text);


--
-- Name: idx_ai_grid_policy_rollout_tasks_claim; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_policy_rollout_tasks_claim ON platform.ai_grid_policy_rollout_tasks USING btree (status, next_retry_at, created_at);


--
-- Name: idx_ai_grid_precision_label_sample; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_precision_label_sample ON platform.ai_grid_precision_labels USING btree (sample_id);


--
-- Name: idx_ai_grid_precision_review_policy; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_precision_review_policy ON platform.ai_grid_precision_reviews USING btree (policy_id, policy_version, created_at DESC);


--
-- Name: idx_ai_grid_precision_sample_review; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_precision_sample_review ON platform.ai_grid_precision_samples USING btree (review_id);


--
-- Name: idx_ai_grid_precision_sample_source_run; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_precision_sample_source_run ON platform.ai_grid_precision_samples USING btree (source_tenant_id, source_run_id, source_assessment_id);


--
-- Name: idx_ai_grid_release_decision_latest; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_release_decision_latest ON platform.ai_grid_release_decisions USING btree (release_id, decided_at DESC);


--
-- Name: idx_ai_grid_release_decision_policy; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_release_decision_policy ON platform.ai_grid_policy_release_decisions USING btree (policy_id, policy_version, decided_at DESC);


--
-- Name: idx_ai_grid_release_decisions_digest; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_release_decisions_digest ON platform.ai_grid_policy_release_decisions USING btree (policy_id, policy_version, package_digest, decision, decided_at DESC);


--
-- Name: idx_ai_grid_release_gate_latest; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_release_gate_latest ON platform.ai_grid_release_gate_evidence USING btree (release_id, gate_code, recorded_at DESC);


--
-- Name: idx_ai_grid_release_gate_material; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_ai_grid_release_gate_material ON platform.ai_grid_release_gate_evidence USING btree (release_id, gate_code, material_digest, recorded_at DESC);


--
-- Name: idx_app_user_global_roles_role; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_app_user_global_roles_role ON platform.app_user_global_roles USING btree (role);


--
-- Name: idx_cpe_dim_key; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_cpe_dim_key ON platform.cpe_dim USING btree (cpe_key);


--
-- Name: idx_cpe_dim_normalized; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_cpe_dim_normalized ON platform.cpe_dim USING btree (normalized_cpe);


--
-- Name: idx_eol_catalog_cpe; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_eol_catalog_cpe ON platform.eol_product_catalog USING btree (cpe_vendor, cpe_product);


--
-- Name: idx_eol_catalog_purl; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_eol_catalog_purl ON platform.eol_product_catalog USING btree (purl_type, purl_namespace);


--
-- Name: idx_eol_release_is_eol; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_eol_release_is_eol ON platform.eol_release USING btree (is_eol);


--
-- Name: idx_eol_release_product_slug; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_eol_release_product_slug ON platform.eol_release USING btree (product_slug);


--
-- Name: idx_identity_links_from; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_identity_links_from ON platform.identity_links USING btree (from_identifier_id);


--
-- Name: idx_identity_links_to; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_identity_links_to ON platform.identity_links USING btree (to_identifier_id);


--
-- Name: idx_personal_finding_queues_owner_order; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_personal_finding_queues_owner_order ON platform.personal_finding_queues USING btree (tenant_id, owner_user_id, display_order, created_at);


--
-- Name: idx_software_eol_mapping_identity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_software_eol_mapping_identity ON platform.software_eol_mapping USING btree (software_identity_id);


--
-- Name: idx_software_eol_mapping_slug; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_software_eol_mapping_slug ON platform.software_eol_mapping USING btree (eol_slug);


--
-- Name: idx_software_identifier_identity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_software_identifier_identity ON platform.software_identifiers USING btree (software_identity_id);


--
-- Name: idx_software_identifier_type_value; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_software_identifier_type_value ON platform.software_identifiers USING btree (id_type, normalized_value);


--
-- Name: idx_software_identity_key; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_software_identity_key ON platform.software_identities USING btree (canonical_key);


--
-- Name: idx_sync_runs_run_scope_started; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_sync_runs_run_scope_started ON platform.sync_runs USING btree (run_scope, started_at DESC);


--
-- Name: idx_sync_runs_sync_type_status; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_sync_runs_sync_type_status ON platform.sync_runs USING btree (lower((sync_type)::text), lower((status)::text), started_at DESC);


--
-- Name: idx_sync_runs_tenant_started; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_sync_runs_tenant_started ON platform.sync_runs USING btree (tenant_id, started_at DESC);


--
-- Name: idx_tenant_entitlement_overrides_tenant; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_entitlement_overrides_tenant ON platform.tenant_entitlement_overrides USING btree (tenant_id);


--
-- Name: idx_tenant_schema_versions_status; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_schema_versions_status ON platform.tenant_schema_versions USING btree (status, current_version);


--
-- Name: idx_tenant_support_grants_subject_status_expires; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_support_grants_subject_status_expires ON platform.tenant_support_grants USING btree (invited_platform_subject, status, expires_at);


--
-- Name: idx_tenant_support_grants_tenant_requested; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_support_grants_tenant_requested ON platform.tenant_support_grants USING btree (tenant_id, requested_at);


--
-- Name: idx_tenant_user_invites_subject_status; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_user_invites_subject_status ON platform.tenant_user_invites USING btree (external_subject, status);


--
-- Name: idx_tenant_user_invites_tenant_created; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_user_invites_tenant_created ON platform.tenant_user_invites USING btree (tenant_id, created_at DESC);


--
-- Name: idx_tenant_user_invites_tenant_status; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_tenant_user_invites_tenant_status ON platform.tenant_user_invites USING btree (tenant_id, status);


--
-- Name: idx_vex_assertions_cpe; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vex_assertions_cpe ON platform.vex_assertions USING btree (cpe_id);


--
-- Name: idx_vex_assertions_identity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vex_assertions_identity ON platform.vex_assertions USING btree (software_identity_id);


--
-- Name: idx_vex_assertions_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vex_assertions_source ON platform.vex_assertions USING btree (source_system);


--
-- Name: idx_vex_assertions_target; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vex_assertions_target ON platform.vex_assertions USING btree (target_id);


--
-- Name: idx_vex_assertions_vulnerability; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vex_assertions_vulnerability ON platform.vex_assertions USING btree (vulnerability_id);


--
-- Name: idx_vintel_summary_cvss_lastmod_updated; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_cvss_lastmod_updated ON platform.vulnerability_intel_summary USING btree (cvss_score, last_modified_at, updated_at);


--
-- Name: idx_vintel_summary_external_cvss_lastmod_updated; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_external_cvss_lastmod_updated ON platform.vulnerability_intel_summary USING btree (external_id, cvss_score, last_modified_at, updated_at);


--
-- Name: idx_vintel_summary_external_id; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_external_id ON platform.vulnerability_intel_summary USING btree (external_id);


--
-- Name: idx_vintel_summary_in_kev; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_in_kev ON platform.vulnerability_intel_summary USING btree (in_kev);


--
-- Name: idx_vintel_summary_severity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_severity ON platform.vulnerability_intel_summary USING btree (severity);


--
-- Name: idx_vintel_summary_source_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_source_source ON platform.vulnerability_intel_summary_sources USING btree (source_system);


--
-- Name: idx_vintel_summary_source_source_vuln; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_source_source_vuln ON platform.vulnerability_intel_summary_sources USING btree (source_system, vulnerability_id);


--
-- Name: idx_vintel_summary_source_vuln; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_source_vuln ON platform.vulnerability_intel_summary_sources USING btree (vulnerability_id);


--
-- Name: idx_vintel_summary_source_vuln_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_source_vuln_source ON platform.vulnerability_intel_summary_sources USING btree (vulnerability_id, source_system);


--
-- Name: idx_vintel_summary_vuln_status; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vintel_summary_vuln_status ON platform.vulnerability_intel_summary USING btree (vuln_status);


--
-- Name: idx_vuln_cfg_expr_source_cfg; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_cfg_expr_source_cfg ON platform.vulnerability_config_expr USING btree (source, config_index);


--
-- Name: idx_vuln_cfg_expr_vuln; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_cfg_expr_vuln ON platform.vulnerability_config_expr USING btree (vulnerability_id);


--
-- Name: idx_vuln_intel_obs_last_seen; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_last_seen ON platform.vulnerability_intel_observations USING btree (last_seen_at);


--
-- Name: idx_vuln_intel_obs_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_source ON platform.vulnerability_intel_observations USING btree (source_system);


--
-- Name: idx_vuln_intel_obs_source_record; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_source_record ON platform.vulnerability_intel_observations USING btree (source_system, source_record_id);


--
-- Name: idx_vuln_intel_obs_source_vuln; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_source_vuln ON platform.vulnerability_intel_observations USING btree (source_system, vulnerability_id);


--
-- Name: idx_vuln_intel_obs_vuln_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_vuln_source ON platform.vulnerability_intel_observations USING btree (vulnerability_id, source_system);


--
-- Name: idx_vuln_intel_obs_vulnerability; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_obs_vulnerability ON platform.vulnerability_intel_observations USING btree (vulnerability_id);


--
-- Name: idx_vuln_intel_relations_from; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_relations_from ON platform.vulnerability_intel_relations USING btree (from_observation_id);


--
-- Name: idx_vuln_intel_relations_source; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_relations_source ON platform.vulnerability_intel_relations USING btree (source_system);


--
-- Name: idx_vuln_intel_relations_to; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_relations_to ON platform.vulnerability_intel_relations USING btree (to_observation_id);


--
-- Name: idx_vuln_intel_relations_type; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_intel_relations_type ON platform.vulnerability_intel_relations USING btree (relation_type);


--
-- Name: idx_vuln_rules_ecosystem_package; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_rules_ecosystem_package ON platform.vulnerability_rules USING btree (ecosystem, package_name);


--
-- Name: idx_vuln_rules_vulnerability; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_rules_vulnerability ON platform.vulnerability_rules USING btree (vulnerability_id);


--
-- Name: idx_vuln_target_cpe_id; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_cpe_id ON platform.vulnerability_targets USING btree (cpe_id);


--
-- Name: idx_vuln_target_identity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_identity ON platform.vulnerability_targets USING btree (software_identity_id);


--
-- Name: idx_vuln_target_package; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_package ON platform.vulnerability_targets USING btree (package_name);


--
-- Name: idx_vuln_target_type_cpe_id; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_type_cpe_id ON platform.vulnerability_targets USING btree (target_type, cpe_id);


--
-- Name: idx_vuln_target_type_key; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_type_key ON platform.vulnerability_targets USING btree (target_type, normalized_target_key);


--
-- Name: idx_vuln_target_vuln; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vuln_target_vuln ON platform.vulnerability_targets USING btree (vulnerability_id);


--
-- Name: idx_vulnerabilities_cvss_lastmod_updated; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_cvss_lastmod_updated ON platform.vulnerabilities USING btree (cvss_score, last_modified_at, updated_at);


--
-- Name: idx_vulnerabilities_epss; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_epss ON platform.vulnerabilities USING btree (epss_score);


--
-- Name: idx_vulnerabilities_external_cvss_lastmod_updated; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_external_cvss_lastmod_updated ON platform.vulnerabilities USING btree (external_id, cvss_score, last_modified_at, updated_at);


--
-- Name: idx_vulnerabilities_in_kev; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_in_kev ON platform.vulnerabilities USING btree (in_kev);


--
-- Name: idx_vulnerabilities_published; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_published ON platform.vulnerabilities USING btree (published_at);


--
-- Name: idx_vulnerabilities_severity; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_vulnerabilities_severity ON platform.vulnerabilities USING btree (severity);


--
-- Name: uk_ai_grid_answer_key_certified_version; Type: INDEX; Schema: platform; Owner: -
--

CREATE UNIQUE INDEX uk_ai_grid_answer_key_certified_version ON platform.ai_grid_answer_key_environments USING btree (environment_key) WHERE ((lifecycle)::text = 'CERTIFIED'::text);


--
-- Name: uk_ai_grid_one_published_policy_version; Type: INDEX; Schema: platform; Owner: -
--

CREATE UNIQUE INDEX uk_ai_grid_one_published_policy_version ON platform.ai_grid_policy_versions USING btree (policy_id) WHERE ((lifecycle)::text = 'PUBLISHED'::text);


--
-- Name: uk_personal_finding_queues_owner_default; Type: INDEX; Schema: platform; Owner: -
--

CREATE UNIQUE INDEX uk_personal_finding_queues_owner_default ON platform.personal_finding_queues USING btree (tenant_id, owner_user_id) WHERE (is_default = true);


--
-- Name: uk_tenant_memberships_user_tenant; Type: INDEX; Schema: platform; Owner: -
--

CREATE UNIQUE INDEX uk_tenant_memberships_user_tenant ON platform.tenant_memberships USING btree (user_id, tenant_id);


--
-- Name: uq_ai_grid_precision_sample_source_assessment; Type: INDEX; Schema: platform; Owner: -
--

CREATE UNIQUE INDEX uq_ai_grid_precision_sample_source_assessment ON platform.ai_grid_precision_samples USING btree (review_id, source_assessment_id) WHERE (source_assessment_id IS NOT NULL);


--
-- Name: idx_finding_list_projection_assigned_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_assigned_status ON public.finding_list_projection USING btree (assigned_to, status);


--
-- Name: idx_finding_list_projection_incident_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_incident_status ON public.finding_list_projection USING btree (incident_id, status);


--
-- Name: idx_finding_list_projection_owner_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_owner_status ON public.finding_list_projection USING btree (owner_group, status);


--
-- Name: idx_finding_list_projection_patch_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_patch_status ON public.finding_list_projection USING btree (patch_available, status);


--
-- Name: idx_finding_list_projection_severity_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_severity_status ON public.finding_list_projection USING btree (severity, status);


--
-- Name: idx_finding_list_projection_status_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_status_due ON public.finding_list_projection USING btree (status, due_at);


--
-- Name: idx_finding_list_projection_support_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_support_status ON public.finding_list_projection USING btree (support_group, status);


--
-- Name: idx_finding_list_projection_suppressed_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_suppressed_status ON public.finding_list_projection USING btree (suppressed_until, status);


--
-- Name: idx_finding_list_projection_updated_tiebreak; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_list_projection_updated_tiebreak ON public.finding_list_projection USING btree (updated_at, finding_id);


--
-- Name: ai_grid_policy_release_decisions ai_grid_policy_release_decisions_immutable; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER ai_grid_policy_release_decisions_immutable BEFORE DELETE OR UPDATE ON platform.ai_grid_policy_release_decisions FOR EACH ROW EXECUTE FUNCTION platform.ai_grid_policy_release_decisions_immutable();


--
-- Name: ai_grid_release_manifest_items ai_grid_release_manifest_immutable; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER ai_grid_release_manifest_immutable BEFORE DELETE OR UPDATE ON platform.ai_grid_release_manifest_items FOR EACH ROW EXECUTE FUNCTION platform.reject_ai_grid_release_manifest_mutation();


--
-- Name: ai_grid_policy_versions trg_ai_grid_approved_package_immutable; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_approved_package_immutable BEFORE UPDATE ON platform.ai_grid_policy_versions FOR EACH ROW EXECUTE FUNCTION platform.prevent_ai_grid_approved_package_mutation();


--
-- Name: ai_grid_policy_versions trg_ai_grid_approved_package_publication; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_approved_package_publication BEFORE INSERT OR UPDATE OF lifecycle, package_digest ON platform.ai_grid_policy_versions FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_approved_package();


--
-- Name: ai_grid_policy_distribution trg_ai_grid_distribution_approval; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_distribution_approval BEFORE INSERT OR UPDATE ON platform.ai_grid_policy_distribution FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_distribution_approval();


--
-- Name: ai_grid_policy_release_decisions trg_ai_grid_pause_revoked_distribution; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_pause_revoked_distribution AFTER UPDATE OF revoked_at ON platform.ai_grid_policy_release_decisions FOR EACH ROW EXECUTE FUNCTION platform.pause_ai_grid_revoked_distribution();


--
-- Name: ai_grid_policy_versions trg_ai_grid_phase_1_preview_digest_change; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_phase_1_preview_digest_change AFTER UPDATE OF package_digest ON platform.ai_grid_policy_versions FOR EACH ROW EXECUTE FUNCTION platform.invalidate_ai_grid_phase_1_preview_on_digest_change();


--
-- Name: ai_grid_policy_rollouts trg_ai_grid_rollout_approval; Type: TRIGGER; Schema: platform; Owner: -
--

CREATE TRIGGER trg_ai_grid_rollout_approval BEFORE INSERT OR UPDATE OF policy_id, new_version, package_digest, approved_package_digest, release_decision_id ON platform.ai_grid_policy_rollouts FOR EACH ROW EXECUTE FUNCTION platform.require_ai_grid_rollout_approval();


--
-- Name: ai_grid_answer_key_cases ai_grid_answer_key_cases_environment_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_cases
    ADD CONSTRAINT ai_grid_answer_key_cases_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES platform.ai_grid_answer_key_environments(id);


--
-- Name: ai_grid_answer_key_results ai_grid_answer_key_results_case_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_results
    ADD CONSTRAINT ai_grid_answer_key_results_case_id_fkey FOREIGN KEY (case_id) REFERENCES platform.ai_grid_answer_key_cases(id);


--
-- Name: ai_grid_answer_key_results ai_grid_answer_key_results_run_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_results
    ADD CONSTRAINT ai_grid_answer_key_results_run_id_fkey FOREIGN KEY (run_id) REFERENCES platform.ai_grid_answer_key_runs(id);


--
-- Name: ai_grid_answer_key_runs ai_grid_answer_key_runs_environment_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_runs
    ADD CONSTRAINT ai_grid_answer_key_runs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES platform.ai_grid_answer_key_environments(id);


--
-- Name: ai_grid_answer_key_runs ai_grid_answer_key_runs_source_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_answer_key_runs
    ADD CONSTRAINT ai_grid_answer_key_runs_source_tenant_id_fkey FOREIGN KEY (source_tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_correlation_precision_reviews ai_grid_correlation_precision_correlation_id_correlation_v_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_correlation_precision_reviews
    ADD CONSTRAINT ai_grid_correlation_precision_correlation_id_correlation_v_fkey FOREIGN KEY (correlation_id, correlation_version) REFERENCES platform.ai_grid_correlation_versions(correlation_id, version);


--
-- Name: ai_grid_phase_1_tenant_migration_audit ai_grid_phase_1_tenant_migration_audit_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_phase_1_tenant_migration_audit
    ADD CONSTRAINT ai_grid_phase_1_tenant_migration_audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_deprecation_tasks ai_grid_policy_deprecation_tasks_deprecation_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecation_tasks
    ADD CONSTRAINT ai_grid_policy_deprecation_tasks_deprecation_id_fkey FOREIGN KEY (deprecation_id) REFERENCES platform.ai_grid_policy_deprecations(id) ON DELETE CASCADE;


--
-- Name: ai_grid_policy_deprecation_tasks ai_grid_policy_deprecation_tasks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_deprecation_tasks
    ADD CONSTRAINT ai_grid_policy_deprecation_tasks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_inactivation_tasks ai_grid_policy_inactivation_tasks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_inactivation_tasks
    ADD CONSTRAINT ai_grid_policy_inactivation_tasks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_release_bindings ai_grid_policy_release_bindings_approval_decision_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_bindings
    ADD CONSTRAINT ai_grid_policy_release_bindings_approval_decision_id_fkey FOREIGN KEY (approval_decision_id) REFERENCES platform.ai_grid_policy_release_decisions(id);


--
-- Name: ai_grid_policy_release_decisions ai_grid_policy_release_decisions_answer_key_run_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_decisions
    ADD CONSTRAINT ai_grid_policy_release_decisions_answer_key_run_id_fkey FOREIGN KEY (answer_key_run_id) REFERENCES platform.ai_grid_answer_key_runs(id);


--
-- Name: ai_grid_policy_release_decisions ai_grid_policy_release_decisions_precision_review_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_release_decisions
    ADD CONSTRAINT ai_grid_policy_release_decisions_precision_review_id_fkey FOREIGN KEY (precision_review_id) REFERENCES platform.ai_grid_precision_reviews(id);


--
-- Name: ai_grid_policy_rollout_tasks ai_grid_policy_rollout_tasks_rollout_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_rollout_id_fkey FOREIGN KEY (rollout_id) REFERENCES platform.ai_grid_policy_rollouts(id) ON DELETE CASCADE;


--
-- Name: ai_grid_policy_rollout_tasks ai_grid_policy_rollout_tasks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_rollout_tasks
    ADD CONSTRAINT ai_grid_policy_rollout_tasks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: ai_grid_policy_versions ai_grid_policy_versions_control_objective_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_versions_control_objective_id_fkey FOREIGN KEY (control_objective_id) REFERENCES platform.ai_grid_control_objectives(control_objective_id);


--
-- Name: ai_grid_precision_adjudications ai_grid_precision_adjudications_sample_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_adjudications
    ADD CONSTRAINT ai_grid_precision_adjudications_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES platform.ai_grid_precision_samples(id);


--
-- Name: ai_grid_precision_labels ai_grid_precision_labels_sample_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_labels
    ADD CONSTRAINT ai_grid_precision_labels_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES platform.ai_grid_precision_samples(id);


--
-- Name: ai_grid_precision_reviews ai_grid_precision_reviews_answer_key_run_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_reviews
    ADD CONSTRAINT ai_grid_precision_reviews_answer_key_run_id_fkey FOREIGN KEY (answer_key_run_id) REFERENCES platform.ai_grid_answer_key_runs(id);


--
-- Name: ai_grid_precision_samples ai_grid_precision_samples_review_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_samples_review_id_fkey FOREIGN KEY (review_id) REFERENCES platform.ai_grid_precision_reviews(id);


--
-- Name: ai_grid_precision_samples ai_grid_precision_samples_source_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.ai_grid_precision_samples
    ADD CONSTRAINT ai_grid_precision_samples_source_tenant_id_fkey FOREIGN KEY (source_tenant_id) REFERENCES platform.tenants(id);


--
-- Name: app_user_global_roles fk_app_user_global_roles_user; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.app_user_global_roles
    ADD CONSTRAINT fk_app_user_global_roles_user FOREIGN KEY (app_user_id) REFERENCES platform.app_users(id);


--
-- Name: finding_queue_preferences fk_finding_queue_preferences_owner; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.finding_queue_preferences
    ADD CONSTRAINT fk_finding_queue_preferences_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users(id);


--
-- Name: finding_queue_preferences fk_finding_queue_preferences_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.finding_queue_preferences
    ADD CONSTRAINT fk_finding_queue_preferences_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: identity_links fk_identity_links_from_identifier; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.identity_links
    ADD CONSTRAINT fk_identity_links_from_identifier FOREIGN KEY (from_identifier_id) REFERENCES platform.software_identifiers(id);


--
-- Name: identity_links fk_identity_links_to_identifier; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.identity_links
    ADD CONSTRAINT fk_identity_links_to_identifier FOREIGN KEY (to_identifier_id) REFERENCES platform.software_identifiers(id);


--
-- Name: personal_finding_queues fk_personal_finding_queues_owner; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.personal_finding_queues
    ADD CONSTRAINT fk_personal_finding_queues_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users(id);


--
-- Name: personal_finding_queues fk_personal_finding_queues_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.personal_finding_queues
    ADD CONSTRAINT fk_personal_finding_queues_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: plan_entitlements fk_plan_entitlements_entitlement_key; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.plan_entitlements
    ADD CONSTRAINT fk_plan_entitlements_entitlement_key FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions(key);


--
-- Name: plan_entitlements fk_plan_entitlements_plan_code; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.plan_entitlements
    ADD CONSTRAINT fk_plan_entitlements_plan_code FOREIGN KEY (plan_code) REFERENCES platform.plan_definitions(code);


--
-- Name: software_identifiers fk_software_identifiers_software_identity; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.software_identifiers
    ADD CONSTRAINT fk_software_identifiers_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: sync_runs fk_sync_runs_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.sync_runs
    ADD CONSTRAINT fk_sync_runs_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: tenant_entitlement_overrides fk_tenant_entitlement_overrides_entitlement_key; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_entitlement_overrides
    ADD CONSTRAINT fk_tenant_entitlement_overrides_entitlement_key FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions(key);


--
-- Name: tenant_entitlement_overrides fk_tenant_entitlement_overrides_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_entitlement_overrides
    ADD CONSTRAINT fk_tenant_entitlement_overrides_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: tenant_memberships fk_tenant_memberships_invited_by; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_memberships
    ADD CONSTRAINT fk_tenant_memberships_invited_by FOREIGN KEY (invited_by) REFERENCES platform.app_users(id);


--
-- Name: tenant_memberships fk_tenant_memberships_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_memberships
    ADD CONSTRAINT fk_tenant_memberships_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: tenant_memberships fk_tenant_memberships_user; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_memberships
    ADD CONSTRAINT fk_tenant_memberships_user FOREIGN KEY (user_id) REFERENCES platform.app_users(id);


--
-- Name: tenant_support_grants fk_tenant_support_grants_accepted_by; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_accepted_by FOREIGN KEY (accepted_by) REFERENCES platform.app_users(id);


--
-- Name: tenant_support_grants fk_tenant_support_grants_granted_by; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_granted_by FOREIGN KEY (granted_by) REFERENCES platform.app_users(id);


--
-- Name: tenant_support_grants fk_tenant_support_grants_revoked_by; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_revoked_by FOREIGN KEY (revoked_by) REFERENCES platform.app_users(id);


--
-- Name: tenant_support_grants fk_tenant_support_grants_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: tenant_user_invites fk_tenant_user_invites_invited_by; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_user_invites
    ADD CONSTRAINT fk_tenant_user_invites_invited_by FOREIGN KEY (invited_by) REFERENCES platform.app_users(id);


--
-- Name: tenant_user_invites fk_tenant_user_invites_tenant; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_user_invites
    ADD CONSTRAINT fk_tenant_user_invites_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);


--
-- Name: vex_assertions fk_vex_assertions_cpe; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT fk_vex_assertions_cpe FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim(id);


--
-- Name: vex_assertions fk_vex_assertions_identity; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT fk_vex_assertions_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: vex_assertions fk_vex_assertions_observation; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT fk_vex_assertions_observation FOREIGN KEY (observation_id) REFERENCES platform.vulnerability_intel_observations(id);


--
-- Name: vex_assertions fk_vex_assertions_target; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT fk_vex_assertions_target FOREIGN KEY (target_id) REFERENCES platform.vulnerability_targets(id);


--
-- Name: vex_assertions fk_vex_assertions_vulnerability; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vex_assertions
    ADD CONSTRAINT fk_vex_assertions_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: vulnerability_config_expr fk_vulnerability_config_expr_vulnerability; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_config_expr
    ADD CONSTRAINT fk_vulnerability_config_expr_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: vulnerability_intel_observations fk_vulnerability_intel_observations_vulnerability; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_observations
    ADD CONSTRAINT fk_vulnerability_intel_observations_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: vulnerability_intel_relations fk_vulnerability_intel_relations_from; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_relations
    ADD CONSTRAINT fk_vulnerability_intel_relations_from FOREIGN KEY (from_observation_id) REFERENCES platform.vulnerability_intel_observations(id);


--
-- Name: vulnerability_intel_relations fk_vulnerability_intel_relations_to; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_intel_relations
    ADD CONSTRAINT fk_vulnerability_intel_relations_to FOREIGN KEY (to_observation_id) REFERENCES platform.vulnerability_intel_observations(id);


--
-- Name: vulnerability_rules fk_vulnerability_rules_vulnerability; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_rules
    ADD CONSTRAINT fk_vulnerability_rules_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: vulnerability_targets fk_vulnerability_targets_cpe; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_targets
    ADD CONSTRAINT fk_vulnerability_targets_cpe FOREIGN KEY (cpe_id) REFERENCES platform.cpe_dim(id);


--
-- Name: vulnerability_targets fk_vulnerability_targets_software_identity; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_targets
    ADD CONSTRAINT fk_vulnerability_targets_software_identity FOREIGN KEY (software_identity_id) REFERENCES platform.software_identities(id);


--
-- Name: vulnerability_targets fk_vulnerability_targets_vulnerability; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.vulnerability_targets
    ADD CONSTRAINT fk_vulnerability_targets_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES platform.vulnerabilities(id);


--
-- Name: tenant_schema_versions tenant_schema_versions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.tenant_schema_versions
    ADD CONSTRAINT tenant_schema_versions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


--
-- PostgreSQL database dump
--


-- Dumped from database version 17.9 (Homebrew)
-- Dumped by pg_dump version 17.9 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: ai_grid_capability_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_capability_definitions (capability_id, provider, connector, resource_family, optional, lifecycle, remediation) FROM stdin;
BEDROCK_AGENTS	AWS	AWS_DISCOVERY	BEDROCK_AGENTS	f	ACTIVE	Grant the read-only Bedrock Agents permissions and run discovery.
BEDROCK_GUARDRAILS	AWS	AWS_DISCOVERY	BEDROCK_GUARDRAILS	f	ACTIVE	Grant the read-only Bedrock Guardrails permissions and run discovery.
BEDROCK_KNOWLEDGE_BASES	AWS	AWS_DISCOVERY	BEDROCK_KNOWLEDGE_BASES	f	ACTIVE	Grant the read-only Bedrock Knowledge Bases permissions and run discovery.
BEDROCK_MODELS_JOBS	AWS	AWS_DISCOVERY	BEDROCK_MODELS_AND_JOBS	f	ACTIVE	Grant the read-only Bedrock models and jobs permissions and run discovery.
BEDROCK_INVOCATION_LOGGING	AWS	AWS_DISCOVERY	BEDROCK_INVOCATION_LOGGING	f	ACTIVE	Grant the read-only Bedrock logging permissions and run discovery.
IAM_ROLE_POLICIES	AWS	AWS_DISCOVERY	IAM_ROLE_POLICIES	f	ACTIVE	Grant the read-only IAM role-policy permissions and run discovery.
LAMBDA_URLS	AWS	AWS_DISCOVERY	LAMBDA_URLS	f	ACTIVE	Grant the read-only Lambda URL permissions and run discovery.
AGENTCORE_GATEWAYS_TARGETS	AWS	AWS_DISCOVERY	AGENTCORE_GATEWAYS_AND_TARGETS	f	ACTIVE	Grant the read-only AgentCore gateway and target permissions and run discovery.
SAGEMAKER_DOMAINS_MODELS_ENDPOINTS	AWS	AWS_DISCOVERY	SAGEMAKER_DOMAINS_MODELS_ENDPOINTS	f	ACTIVE	Grant the read-only SageMaker permissions and run discovery.
MACIE_CLASSIFICATION	AWS	AWS_MACIE	MACIE_CLASSIFICATION	t	ACTIVE	Enable the read-only Macie classification integration for the applicable account.
AI_ACCOUNTS	AZURE	AZURE_DISCOVERY	AI_ACCOUNTS	f	ACTIVE	Grant the read-only Azure AI Account permissions and run discovery.
DIAGNOSTIC_SETTINGS	AZURE	AZURE_DISCOVERY	DIAGNOSTIC_SETTINGS	f	ACTIVE	Grant the read-only diagnostic settings permissions and run discovery.
FOUNDRY_DEPLOYMENTS_RAI	AZURE	AZURE_DISCOVERY	FOUNDRY_DEPLOYMENTS_AND_RAI	f	ACTIVE	Grant the read-only Foundry deployment and RAI permissions and run discovery.
FOUNDRY_AGENTS_TOOLS	AZURE	AZURE_DISCOVERY	FOUNDRY_AGENTS_AND_TOOLS	t	ACTIVE	Enable the read-only Foundry agent and tool metadata collection.
ML_WORKSPACES_ENDPOINTS	AZURE	AZURE_DISCOVERY	ML_WORKSPACES_AND_ENDPOINTS	f	ACTIVE	Grant the read-only Azure ML workspace and endpoint permissions and run discovery.
SEARCH_CONTROL_PLANE	AZURE	AZURE_DISCOVERY	SEARCH_CONTROL_PLANE	f	ACTIVE	Grant the read-only Azure AI Search control-plane permissions and run discovery.
BOT_CONFIGURATION	AZURE	AZURE_DISCOVERY	BOT_CONFIGURATION	f	ACTIVE	Grant the read-only Azure Bot configuration permissions and run discovery.
RBAC_ASSIGNMENTS	AZURE	AZURE_DISCOVERY	RBAC_ASSIGNMENTS	f	ACTIVE	Grant the read-only Azure RBAC assignment permissions and run discovery.
PURVIEW_CLASSIFICATION	AZURE	AZURE_PURVIEW	PURVIEW_CLASSIFICATION	t	ACTIVE	Enable the read-only Purview classification integration for the applicable subscription.
FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE	AZURE	AZURE_DISCOVERY	FOUNDRY_AGENTS_SEARCH_DATA_PLANE	t	ACTIVE	Enable the required read-only Foundry Agents or Search data-plane metadata collection.
MULTI_CLOUD_GRAPH	MULTI_CLOUD	AI_GRID_GRAPH	DIRECT_RELATIONSHIPS	f	ACTIVE	Collect complete, fresh direct relationship evidence for the coverage epoch.
AWS_EFFECTIVE_ACCESS	AWS	AWS_DISCOVERY	EFFECTIVE_ACCESS	f	ACTIVE	Collect bounded IAM simulation and Access Analyzer decisions for discovered AI principals.
AWS_LINKED_DATA_STORES	AWS	AWS_DISCOVERY	LINKED_DATA_STORES	f	ACTIVE	Collect read-only metadata for directly referenced AI data stores and AgentCore endpoints.
AWS_CONSUMPTION_TELEMETRY	AWS	AWS_DISCOVERY	CONSUMPTION_TELEMETRY	f	ACTIVE	Collect aggregated Bedrock quota, budget, alarm, invocation, and token metadata.
AWS_MODEL_DATA_PROVENANCE	AWS	AWS_DISCOVERY	MODEL_DATA_PROVENANCE	f	ACTIVE	Collect bounded model, dataset, registry, SBOM, and vulnerability provenance metadata.
AZURE_EFFECTIVE_ACCESS	AZURE	AZURE_DISCOVERY	EFFECTIVE_ACCESS	f	ACTIVE	Collect bounded Azure role, deny-assignment, and effective-access metadata for discovered AI principals.
AZURE_LINKED_DATA_STORES	AZURE	AZURE_DISCOVERY	LINKED_DATA_STORES	f	ACTIVE	Collect read-only metadata for directly linked Storage, OneLake, and Search resources.
AZURE_SEARCH_MCP_SECURITY	AZURE	AZURE_DISCOVERY	SEARCH_MCP_SECURITY	f	ACTIVE	Collect secret-safe Search, Bot, and Foundry MCP security classifications.
AZURE_CONSUMPTION_TELEMETRY	AZURE	AZURE_DISCOVERY	CONSUMPTION_TELEMETRY	f	ACTIVE	Collect aggregated Azure Monitor quota, budget, alert, request, and token metadata.
AZURE_MODEL_DATA_PROVENANCE	AZURE	AZURE_DISCOVERY	MODEL_DATA_PROVENANCE	f	ACTIVE	Collect bounded Azure ML, registry, MLflow, SBOM, and vulnerability provenance metadata.
\.


--
-- Data for Name: ai_grid_control_objectives; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_control_objectives (control_objective_id, name, security_intent, remediation_intent, owner, lifecycle, created_at) FROM stdin;
AGCF-OBJ-AWS-001	Bedrock agent has no guardrail attached	Prevent the risk condition described by AGCF-AWS-001.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-002	Attached Bedrock guardrail is below the configured minimum strength	Prevent the risk condition described by AGCF-AWS-002.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-003	Bedrock agent is not in an approved operational state	Prevent the risk condition described by AGCF-AWS-003.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-004	Bedrock agent execution role is missing	Prevent the risk condition described by AGCF-AWS-004.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-005	Bedrock execution role contains wildcard actions	Prevent the risk condition described by AGCF-AWS-005.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-006	Action-group Lambda URL permits unauthenticated invocation	Prevent the risk condition described by AGCF-AWS-006.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-007	Agent foundation model is outside the tenant-approved allowlist	Prevent the risk condition described by AGCF-AWS-007.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-008	Agent action-group Lambda target is outside the approved target allowlist	Prevent the risk condition described by AGCF-AWS-008.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-009	Bedrock model invocation logging is disabled	Prevent the risk condition described by AGCF-AWS-009.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-010	Bedrock guardrail is failed, deleting, or otherwise non-active	Prevent the risk condition described by AGCF-AWS-010.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-011	Bedrock guardrail lacks a customer-managed KMS key where CMK is required	Prevent the risk condition described by AGCF-AWS-011.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-012	Bedrock guardrail has no configured content filters	Prevent the risk condition described by AGCF-AWS-012.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-013	Sensitive-data agent lacks configured PII guardrail entities	Prevent the risk condition described by AGCF-AWS-013.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-014	Grounded-generation baseline requires contextual grounding filters, but none are configured	Prevent the risk condition described by AGCF-AWS-014.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-015	Denied-topic baseline is required, but no denied topics are configured	Prevent the risk condition described by AGCF-AWS-015.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-016	Guardrail configuration has not been reviewed within the configured maximum age	Prevent the risk condition described by AGCF-AWS-016.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-017	Bedrock knowledge base uses an S3 source with public policy exposure	Prevent the risk condition described by AGCF-AWS-017.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-018	Bedrock knowledge base is failed or unavailable	Prevent the risk condition described by AGCF-AWS-018.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-019	Bedrock data source is failed or unavailable	Prevent the risk condition described by AGCF-AWS-019.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-020	Bedrock data-source configuration is absent	Prevent the risk condition described by AGCF-AWS-020.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-021	Bedrock data-source type is outside the approved source allowlist	Prevent the risk condition described by AGCF-AWS-021.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-022	Bedrock data deletion policy violates the tenant retention baseline	Prevent the risk condition described by AGCF-AWS-022.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-023	AI data store has unknown, failed, or stale sensitivity classification	Prevent the risk condition described by AGCF-AWS-023.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-024	Macie-confirmed sensitive AI data store permits public content access	Prevent the risk condition described by AGCF-AWS-024.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-025	Bedrock custom model lacks a customer-managed KMS key where required	Prevent the risk condition described by AGCF-AWS-025.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-026	Bedrock imported model lacks a customer-managed KMS key where required	Prevent the risk condition described by AGCF-AWS-026.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-027	Referenced foundation model lifecycle is not ACTIVE	Prevent the risk condition described by AGCF-AWS-027.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-028	Model provider or model identifier is outside the approved allowlist	Prevent the risk condition described by AGCF-AWS-028.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-029	Bedrock custom/imported model or customization job is in a failed terminal state	Prevent the risk condition described by AGCF-AWS-029.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-030	Provisioned model or inference profile is in an unhealthy state	Prevent the risk condition described by AGCF-AWS-030.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-031	AgentCore gateway inbound authorization is missing or outside the approved auth types	Prevent the risk condition described by AGCF-AWS-031.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-032	AgentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types	Prevent the risk condition described by AGCF-AWS-032.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-033	AgentCore target is failed, unsynchronized, or stale beyond the configured age	Prevent the risk condition described by AGCF-AWS-033.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-034	MCP target subtype or server hostname is outside the tenant allowlist	Prevent the risk condition described by AGCF-AWS-034.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-035	SageMaker domain lacks VPC attachment	Prevent the risk condition described by AGCF-AWS-035.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-036	SageMaker endpoint, model package, or execution space is in a failed terminal state	Prevent the risk condition described by AGCF-AWS-036.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-037	SageMaker notebook instance type is outside the approved compute baseline	Prevent the risk condition described by AGCF-AWS-037.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AWS-038	Bedrock flow is failed or outside the approved lifecycle state	Prevent the risk condition described by AGCF-AWS-038.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-001	Azure AI, ML workspace, or Search service permits unrestricted public network access	Prevent the risk condition described by AGCF-AZR-001.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-002	Private endpoint is absent where the tenant baseline requires one	Prevent the risk condition described by AGCF-AZR-002.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-003	Azure AI account permits local/key authentication	Prevent the risk condition described by AGCF-AZR-003.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-004	Azure AI account lacks customer-managed-key encryption where required	Prevent the risk condition described by AGCF-AZR-004.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-005	Azure AI diagnostic logging is disabled	Prevent the risk condition described by AGCF-AZR-005.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-006	Diagnostic settings have no enabled destination	Prevent the risk condition described by AGCF-AZR-006.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-007	Managed AI resource provisioning state is failed or non-succeeded	Prevent the risk condition described by AGCF-AZR-007.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-008	Managed AI resource lacks a confirmed owner tag	Prevent the risk condition described by AGCF-AZR-008.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-009	Managed AI resource lacks required environment or criticality tags	Prevent the risk condition described by AGCF-AZR-009.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-010	Azure RAI policy explicitly disables or does not block a returned filter	Prevent the risk condition described by AGCF-AZR-010.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-011	Azure RAI policy has no content-filter definitions	Prevent the risk condition described by AGCF-AZR-011.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-012	Foundry deployment has no RAI policy reference	Prevent the risk condition described by AGCF-AZR-012.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-013	RAI mode or base policy is outside the approved baseline	Prevent the risk condition described by AGCF-AZR-013.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-014	Required custom blocklist baseline is absent	Prevent the risk condition described by AGCF-AZR-014.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-015	Foundry model name or publisher is outside the approved allowlist	Prevent the risk condition described by AGCF-AZR-015.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-016	Foundry model version or upgrade option violates the patch/lifecycle baseline	Prevent the risk condition described by AGCF-AZR-016.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-017	Foundry agent has Code Interpreter enabled outside an approved scope	Prevent the risk condition described by AGCF-AZR-017.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-018	Foundry agent model deployment is absent or outside the approved allowlist	Prevent the risk condition described by AGCF-AZR-018.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-019	Foundry MCP server uses NONE or UNKNOWN configured authentication	Prevent the risk condition described by AGCF-AZR-019.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-020	Foundry MCP server hostname is outside the approved allowlist	Prevent the risk condition described by AGCF-AZR-020.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-021	Foundry agent uses a tool type outside the approved tool allowlist	Prevent the risk condition described by AGCF-AZR-021.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-022	Azure ML online endpoint permits local/key authentication	Prevent the risk condition described by AGCF-AZR-022.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-023	Azure ML endpoint traffic references a missing or non-ready deployment	Prevent the risk condition described by AGCF-AZR-023.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-024	Azure ML deployment instance type or model reference is outside the approved baseline	Prevent the risk condition described by AGCF-AZR-024.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-025	Azure ML job or pipeline is in a failed terminal state	Prevent the risk condition described by AGCF-AZR-025.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-026	Azure AI Search permits local admin-key authentication	Prevent the risk condition described by AGCF-AZR-026.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-027	Azure Bot uses password authentication without managed identity	Prevent the risk condition described by AGCF-AZR-027.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-028	Azure Bot has no managed identity where the baseline requires one	Prevent the risk condition described by AGCF-AZR-028.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-029	Azure Bot channel is outside the approved channel allowlist	Prevent the risk condition described by AGCF-AZR-029.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-030	High-privilege Azure role assignment is broader than the approved AI resource scope	Prevent the risk condition described by AGCF-AZR-030.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-031	High-privilege Azure role assignment lacks the required condition or approved principal type	Prevent the risk condition described by AGCF-AZR-031.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-AZR-032	AI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification	Prevent the risk condition described by AGCF-AZR-032.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-001	Publicly reachable AI service has a direct path to confirmed sensitive data	Prevent the risk condition described by AGCF-XSP-001.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-002	Code Interpreter or another high-impact tool has a direct path to confirmed sensitive data	Prevent the risk condition described by AGCF-XSP-002.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-003	Wildcard or broad identity permissions reach a high-impact agent tool	Prevent the risk condition described by AGCF-XSP-003.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-004	External or unapproved MCP server is reachable from an agent that can access sensitive data	Prevent the risk condition described by AGCF-XSP-004.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-005	Agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth	Prevent the risk condition described by AGCF-XSP-005.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-XSP-006	Agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline	Prevent the risk condition described by AGCF-XSP-006.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.868808+05:30
AGCF-OBJ-P2-AWS-039	Effective agent permissions exceed the approved action/resource matrix	Prevent the risk condition described by AGCF-AWS-039.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-040	Effective agent permissions allow cross-account sensitive-resource access	Prevent the risk condition described by AGCF-AWS-040.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-041	Agent can pass or assume an unapproved privileged role	Prevent the risk condition described by AGCF-AWS-041.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-042	Boundaries or organization controls fail to restrict consequential actions	Prevent the risk condition described by AGCF-AWS-042.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-043	AI-linked S3 effective Block Public Access is incomplete	Prevent the risk condition described by AGCF-AWS-043.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-044	AI-linked S3 default encryption is absent	Prevent the risk condition described by AGCF-AWS-044.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-045	AI-linked S3 lacks a required customer-managed key	Prevent the risk condition described by AGCF-AWS-045.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-046	AI-linked S3 permits unapproved cross-account principals	Prevent the risk condition described by AGCF-AWS-046.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-047	AI-linked S3 does not enforce TLS	Prevent the risk condition described by AGCF-AWS-047.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-048	Referenced vector store permits public network access	Prevent the risk condition described by AGCF-AWS-048.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-049	Referenced vector store lacks required encryption	Prevent the risk condition described by AGCF-AWS-049.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-050	Vector-store access policy lacks an approved tenant/principal boundary	Prevent the risk condition described by AGCF-AWS-050.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-051	Bedrock consumption budget is absent	Prevent the risk condition described by AGCF-AWS-051.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-052	Bedrock quota-utilization alarm is absent	Prevent the risk condition described by AGCF-AWS-052.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-053	Bedrock quota utilization exceeds the configured threshold	Prevent the risk condition described by AGCF-AWS-053.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-054	Bedrock throttling exceeds threshold without an effective alarm	Prevent the risk condition described by AGCF-AWS-054.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-055	Bedrock token or invocation consumption exceeds threshold	Prevent the risk condition described by AGCF-AWS-055.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-056	Deployed model artifact lacks signature or attestation	Prevent the risk condition described by AGCF-AWS-056.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-057	Deployed model lacks approved registry lineage	Prevent the risk condition described by AGCF-AWS-057.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-058	Deployed model lacks AI-BOM/SBOM coverage	Prevent the risk condition described by AGCF-AWS-058.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-059	Referenced model-serving artifact has high/critical vulnerabilities	Prevent the risk condition described by AGCF-AWS-059.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-060	Training or retrieval dataset version/checksum is not pinned	Prevent the risk condition described by AGCF-AWS-060.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-061	Dataset provenance or ingestion lineage is missing	Prevent the risk condition described by AGCF-AWS-061.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-062	Referenced dataset changed after approved ingestion	Prevent the risk condition described by AGCF-AWS-062.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-063	AgentCore/MCP endpoint is public without adequate authentication	Prevent the risk condition described by AGCF-AWS-063.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-064	MCP endpoint does not meet the configured TLS baseline	Prevent the risk condition described by AGCF-AWS-064.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-065	SageMaker network isolation is disabled	Prevent the risk condition described by AGCF-AWS-065.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-066	SageMaker storage lacks a required customer-managed key	Prevent the risk condition described by AGCF-AWS-066.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-067	SageMaker root access is enabled	Prevent the risk condition described by AGCF-AWS-067.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-068	SageMaker image integrity or vulnerability baseline fails	Prevent the risk condition described by AGCF-AWS-068.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-033	Effective AI principal permissions exceed the approved matrix	Prevent the risk condition described by AGCF-AZR-033.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-034	Effective AI principal reaches sensitive resources outside approved scope	Prevent the risk condition described by AGCF-AZR-034.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-035	AI principal can create role assignments or elevate access	Prevent the risk condition described by AGCF-AZR-035.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-036	Custom AI role contains high-impact wildcard permissions	Prevent the risk condition described by AGCF-AZR-036.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-037	AI-linked role assignment is stale beyond the baseline	Prevent the risk condition described by AGCF-AZR-037.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-038	Required PIM activation is absent	Prevent the risk condition described by AGCF-AZR-038.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-039	Required access review is absent or stale	Prevent the risk condition described by AGCF-AZR-039.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-040	Search data source uses key, SAS, or secret authentication	Prevent the risk condition described by AGCF-AZR-040.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-041	Search connection lacks required CMK protection	Prevent the risk condition described by AGCF-AZR-041.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-042	Search index lacks required permission filtering	Prevent the risk condition described by AGCF-AZR-042.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-043	Search index lacks document-level authorization	Prevent the risk condition described by AGCF-AZR-043.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-044	Search index lacks tenant partitioning	Prevent the risk condition described by AGCF-AZR-044.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-045	Search retrieval mode is outside the approved baseline	Prevent the risk condition described by AGCF-AZR-045.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-046	Search service or object lacks required CMK encryption	Prevent the risk condition described by AGCF-AZR-046.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-047	Search outbound shared-private-link control is absent	Prevent the risk condition described by AGCF-AZR-047.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-048	AI-linked Storage permits public blob access	Prevent the risk condition described by AGCF-AZR-048.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-049	AI-linked Storage permits shared-key access	Prevent the risk condition described by AGCF-AZR-049.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-050	AI-linked Storage fails secure-transfer or minimum-TLS requirements	Prevent the risk condition described by AGCF-AZR-050.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-051	AI-linked Storage lacks required CMK encryption	Prevent the risk condition described by AGCF-AZR-051.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-052	AI-linked Storage uses default-allow networking without a private endpoint	Prevent the risk condition described by AGCF-AZR-052.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-053	Azure AI consumption budget is absent	Prevent the risk condition described by AGCF-AZR-053.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-054	Quota-utilization alert is absent	Prevent the risk condition described by AGCF-AZR-054.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-055	Quota utilization exceeds threshold	Prevent the risk condition described by AGCF-AZR-055.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-056	Throttling or capacity saturation exceeds threshold	Prevent the risk condition described by AGCF-AZR-056.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-057	Token or request consumption exceeds threshold	Prevent the risk condition described by AGCF-AZR-057.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-058	Deployed model lacks signature or attestation	Prevent the risk condition described by AGCF-AZR-058.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-059	Deployed model lacks approved registry lineage	Prevent the risk condition described by AGCF-AZR-059.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-060	Deployed model lacks AI-BOM/SBOM coverage	Prevent the risk condition described by AGCF-AZR-060.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-061	Referenced deployment image has high/critical vulnerabilities	Prevent the risk condition described by AGCF-AZR-061.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-062	Training or retrieval dataset version/checksum is not pinned	Prevent the risk condition described by AGCF-AZR-062.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-063	MLflow or dataset lineage is missing	Prevent the risk condition described by AGCF-AZR-063.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-064	Azure ML workspace managed network is absent	Prevent the risk condition described by AGCF-AZR-064.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-065	Azure ML deployment has unrestricted outbound egress	Prevent the risk condition described by AGCF-AZR-065.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-066	Bot endpoint is publicly exposed without strong authentication	Prevent the risk condition described by AGCF-AZR-066.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-067	Bot uses secret-based credentials where managed identity is required	Prevent the risk condition described by AGCF-AZR-067.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-068	Bot endpoint fails the configured TLS baseline	Prevent the risk condition described by AGCF-AZR-068.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-069	Foundry MCP lacks the required private endpoint	Prevent the risk condition described by AGCF-AZR-069.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-069	Authoritative effective public-access evidence for the linked S3 resource	Prevent the risk condition described by AGCF-AWS-069.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-070	Confirmed sensitivity plus authoritative effective public-content access	Prevent the risk condition described by AGCF-AWS-070.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-071	Authoritative AgentCore gateway inbound-auth classification and completeness	Prevent the risk condition described by AGCF-AWS-071.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AWS-072	Authoritative AgentCore target outbound-auth classification and completeness	Prevent the risk condition described by AGCF-AWS-072.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-070	Authoritative effective public-network exposure for the linked AI resource	Prevent the risk condition described by AGCF-AZR-070.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-071	Authoritative private-path requirement and effective private-endpoint evidence	Prevent the risk condition described by AGCF-AZR-071.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-072	Secret-safe authoritative Foundry MCP authentication classification	Prevent the risk condition described by AGCF-AZR-072.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-073	Effective privileged RBAC reach outside the approved AI scope	Prevent the risk condition described by AGCF-AZR-073.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-074	Effective role constraints, deny assignments, condition, and approved-principal evidence	Prevent the risk condition described by AGCF-AZR-074.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-AZURE-075	Authoritative sensitivity state with explicit unknown/failed/stale handling	Prevent the risk condition described by AGCF-AZR-075.	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-007	Effective public entry point reaches an authoritatively confirmed sensitive store	Prevent the exposure condition described by AGCF-XSP-007.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-008	Effective consequential tool permission reaches an authoritative sensitive-data path	Prevent the exposure condition described by AGCF-XSP-008.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-009	Effective IAM/RBAC decision reaches a high-impact agent tool	Prevent the exposure condition described by AGCF-XSP-009.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-010	Authoritatively unapproved/external MCP path reaches sensitive data through the agent	Prevent the exposure condition described by AGCF-XSP-010.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-011	Secret-safe MCP auth classification plus effective high-impact tool permissions validates the path	Prevent the exposure condition described by AGCF-XSP-011.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
AGCF-OBJ-P2-XSP-012	Search ACL, tenant isolation, retrieval mode, and sensitive-data evidence validate the retrieval path	Prevent the exposure condition described by AGCF-XSP-012.	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	AI Grid Security	ACTIVE	2026-09-03 07:14:18.968589+05:30
\.


--
-- Data for Name: ai_grid_correlation_versions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_correlation_versions (correlation_id, version, name, description, lifecycle, severity, precision_threshold, max_path_depth, max_fan_out, allowed_node_types_json, allowed_edge_types_json, requirements_json, approved_by, approved_at, published_at, created_at) FROM stdin;
R2_EXTERNAL_SENSITIVE_ACCESS	1.0.0	Externally reachable AI path to sensitive data	Verified external reachability, inadequate authentication, and confirmed sensitive-data access.	PUBLISHED	CRITICAL	0.95	6	100	["AI_AGENT", "AI_MODEL", "KNOWLEDGE_BASE", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["USES_MODEL", "USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE", "READS_FROM_S3", "USES_SEARCH_INDEX", "DEPLOYS_MODEL", "HAS_DEPLOYMENT", "INVOKES_LAMBDA"]	{"validated": ["network.internet_reachability_verified", "identity.inadequate_authentication_verified", "data.sensitive_access_confirmed"], "hypothesis": ["network.public_access_configured", "identity.local_auth_enabled_configured", "data.source_linked"]}	ai-grid-bootstrap	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30
R2_EXCESSIVE_TOOL_PRIVILEGE	1.0.0	Tool-enabled agent with excessive privilege	Tool-enabled agent with derived excessive effective privilege and secret or consequential-action access.	PUBLISHED	HIGH	0.93	6	100	["AI_AGENT", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["USES_TOOL", "INVOKES_LAMBDA", "ASSUMES_ROLE", "HAS_ROLE_ASSIGNMENT", "USES_KEY_VAULT_KEY"]	{"validated": ["identity.effective_excessive_privilege_derived", "impact.secret_or_consequential_access_confirmed"], "hypothesis": ["identity.wildcard_permission_observed"]}	ai-grid-bootstrap	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30
R2_UNTRUSTED_AUTONOMOUS_EXECUTION	1.0.0	Untrusted input to inadequately controlled autonomous execution	Untrusted input or retrieval reaches autonomous execution without adequate guardrail, isolation, or approval.	PUBLISHED	HIGH	0.92	6	100	["AI_AGENT", "AI_GUARDRAIL", "KNOWLEDGE_BASE", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["USES_TOOL", "INVOKES_LAMBDA", "USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE", "USES_SEARCH_INDEX", "USES_GUARDRAIL"]	{"validated": ["input.untrusted_path_verified", "agent.autonomous_execution_verified", "control.execution_boundary_inadequate_verified"], "hypothesis": ["data.source_linked", "agent.code_interpreter_enabled_configured", "bedrock.agent.guardrail_attached_configured"]}	ai-grid-bootstrap	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30	2026-09-03 07:14:18.830714+05:30
R2_EXTERNAL_MCP_SENSITIVE_ACCESS	1.0.0	External or unapproved MCP path to sensitive data	An MCP server that is externally reachable or unapproved is connected to an AI path with confirmed sensitive-data access.	PUBLISHED	CRITICAL	0.95	6	100	["AI_AGENT", "KNOWLEDGE_BASE", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["EXPOSES_MCP", "CONNECTS_TO_MCP", "CONTAINS_MCP_TARGET", "USES_DATA_SOURCE", "USES_SEARCH_INDEX", "READS_FROM_S3"]	{"validated": ["mcp.external_or_unapproved_verified", "data.sensitive_access_confirmed"], "hypothesis": ["mcp.configured_auth_type", "mcp.inbound_auth_type", "mcp.outbound_auth_type", "data.source_linked"]}	ai-grid-phase-1	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30
R2_MCP_WEAK_AUTH_EXECUTION	1.0.0	High-impact execution through an MCP target with weak authentication	An autonomous or high-impact AI agent routes through an MCP target whose authentication is absent or unknown.	PUBLISHED	HIGH	0.93	6	100	["AI_AGENT", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["USES_TOOL", "EXPOSES_MCP", "CONNECTS_TO_MCP", "CONTAINS_MCP_TARGET", "INVOKES_LAMBDA"]	{"validated": ["agent.autonomous_execution_verified", "mcp.auth_inadequate_verified"], "hypothesis": ["agent.code_interpreter_enabled_configured", "mcp.configured_auth_type", "mcp.inbound_auth_type", "mcp.outbound_auth_type"]}	ai-grid-phase-1	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30
R2_SENSITIVE_RETRIEVAL_CONTROL_GAP	1.0.0	Sensitive retrieval path without required guardrail or PII baseline	An agent can retrieve sensitive data while the required guardrail or PII-filter baseline is absent.	PUBLISHED	HIGH	0.92	6	100	["AI_AGENT", "AI_GUARDRAIL", "KNOWLEDGE_BASE", "SUPPORTING_RESOURCE", "OTHER_AI_ARTIFACT"]	["USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE", "USES_SEARCH_INDEX", "USES_GUARDRAIL", "READS_FROM_S3"]	{"validated": ["data.sensitive_access_confirmed", "control.execution_boundary_inadequate_verified"], "hypothesis": ["data.source_linked", "bedrock.agent.guardrail_attached_configured", "bedrock.guardrail.minimum_strength_configured", "guardrail.rai_non_blocking_filter_observed"]}	ai-grid-phase-1	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30	2026-09-03 07:14:18.881483+05:30
\.


--
-- Data for Name: ai_grid_fact_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_fact_definitions (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds, lifecycle, created_at) FROM stdin;
bedrock.agent.guardrail_attached_configured	1.0.0	BOOLEAN	Provider configuration states that the agent has an attached guardrail.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.788519+05:30
bedrock.guardrail.minimum_strength_configured	1.0.0	STRING	Minimum configured input/output strength across the attached guardrail content filters.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.788519+05:30
network.public_access_configured	1.0.0	BOOLEAN	Provider configuration permits public network access.	["CONFIGURATION"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.788519+05:30
network.internet_reachability_verified	1.0.0	BOOLEAN	An approved reachability method verified an Internet path.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.788519+05:30
data.s3_public_access_configured	1.0.0	BOOLEAN	Provider configuration indicates that a knowledge-base S3 source is public.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
compute.lambda_url_auth_type_configured	1.0.0	STRING	Effective configured authentication type across agent action-group Lambda URLs.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.wildcard_permission_observed	1.0.0	BOOLEAN	A syntactic wildcard action was observed in the directly inspected execution-role policies.	["CONFIGURATION"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
logging.model_invocation_enabled_configured	1.0.0	BOOLEAN	Bedrock model invocation logging is configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.local_auth_enabled_configured	1.0.0	BOOLEAN	Provider configuration permits key-based local authentication.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
logging.diagnostic_enabled_configured	1.0.0	BOOLEAN	An approved diagnostic logging destination is configured and enabled.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
agent.code_interpreter_enabled_configured	1.0.0	BOOLEAN	The agent configuration enables Code Interpreter.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.ml_endpoint_local_auth_enabled_configured	1.0.0	BOOLEAN	The Azure ML endpoint permits local key authentication.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.search_local_admin_auth_enabled_configured	1.0.0	BOOLEAN	Azure AI Search local admin-key authentication is enabled.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.search_data_source_non_identity_auth_observed	1.0.0	BOOLEAN	Authoritative configuration shows non-identity authentication for the Search data source.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.bot_password_without_managed_identity_observed	1.0.0	BOOLEAN	Bot password authentication is configured without an assigned managed identity.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
data.customer_managed_key_configured	1.0.0	BOOLEAN	Provider configuration declares customer-managed-key encryption.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
network.private_endpoint_count_configured	1.0.0	NUMBER	Number of configured private endpoint connections observed from provider configuration.	["CONFIGURATION"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
owner.tag_candidate	1.0.0	OBJECT	Unverified ownership candidate derived from provider resource tags.	["CONFIGURATION"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
agent.status_observed	1.0.0	STRING	Provider-reported lifecycle status for the AI agent.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.execution_role_present_configured	1.0.0	BOOLEAN	Agent configuration contains a non-empty execution role identifier.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.794726+05:30
identity.effective_admin_access_derived	1.0.0	BOOLEAN	Effective administrative access derived from an approved identity graph and authorization model.	["GRAPH_ANALYSIS"]	["EXPOSURE_HYPOTHESIS", "VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.818426+05:30
data.source_linked	1.0.0	BOOLEAN	A provider or graph relationship links the AI artifact to a data source; this does not classify content.	["RELATIONSHIP_GRAPH"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.818426+05:30
data.sensitive_content_confirmed	1.0.0	BOOLEAN	An approved data-classification method confirmed sensitive content reachable from the AI system.	["DATA_CLASSIFICATION", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.818426+05:30
owner.confirmed	1.0.0	OBJECT	An authorized user or approved service-catalog mapping confirmed the accountable owner.	["USER_ASSERTION", "SERVICE_CATALOG"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	\N	ACTIVE	2026-09-03 07:14:18.818426+05:30
guardrail.rai_non_blocking_filter_observed	1.0.0	BOOLEAN	Every returned RAI content-filter entry had explicit enabled and blocking booleans; true means at least one entry was disabled or non-blocking.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.82034+05:30
guardrail.rai_policy_reference_configured	1.0.0	STRING	Provider configuration names the RAI policy associated with an Azure model deployment.	["CONFIGURATION"]	["POSTURE_FINDING", "EXPOSURE_HYPOTHESIS"]	86400	ACTIVE	2026-09-03 07:14:18.82034+05:30
identity.inadequate_authentication_verified	1.0.0	BOOLEAN	An approved identity analysis verified inadequate authentication on the exposure entry path.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
data.sensitive_access_confirmed	1.0.0	BOOLEAN	Approved data-security evidence confirms that the path can access sensitive data.	["DSPM", "GRAPH_ANALYSIS", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
identity.effective_excessive_privilege_derived	1.0.0	BOOLEAN	A versioned identity graph derived excessive effective privilege.	["GRAPH_ANALYSIS"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
impact.secret_or_consequential_access_confirmed	1.0.0	BOOLEAN	Approved evidence confirms secret access or a consequential action.	["CIEM", "GRAPH_ANALYSIS", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
input.untrusted_path_verified	1.0.0	BOOLEAN	An approved method verified an untrusted input or retrieval path.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
agent.autonomous_execution_verified	1.0.0	BOOLEAN	Approved evidence verifies autonomous execution on the path.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
control.execution_boundary_inadequate_verified	1.0.0	BOOLEAN	Approved evidence verifies inadequate guardrail, isolation, or approval controls.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.830714+05:30
mcp.endpoint_exposure	1.0.0	STRING	Provider configuration reports an MCP endpoint exposure classification.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.850569+05:30
mcp.configured_auth_type	1.0.0	STRING	Provider configuration reports MCP authentication classification without credentials or headers.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.850569+05:30
mcp.target_status	1.0.0	STRING	Provider control plane reports the managed MCP target status.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.850569+05:30
data.sensitivity_confirmed	1.0.0	BOOLEAN	Macie or Purview confirmed sensitive content for the data store.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.850569+05:30
data.public_content_access_configured	1.0.0	BOOLEAN	Provider configuration confirms that data content is publicly accessible.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.850569+05:30
data.source_type	1.0.0	STRING	Provider-reported AI data-source type.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
data.source_acl_enforced	1.0.0	BOOLEAN	Provider-reported data-source ACL enforcement state.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
data.source_public_content_access	1.0.0	BOOLEAN	Provider-reported public content-access state for an AI data source or store.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
data.source_sensitivity	1.0.0	STRING	Authoritative sensitivity state; missing or failed classification remains UNKNOWN.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
data.sensitivity_source	1.0.0	STRING	Authoritative sensitivity-classification provider.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
data.retrieval_mode	1.0.0	STRING	Provider-reported retrieval mode.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
mcp.inbound_auth_type	1.0.0	STRING	Provider-reported inbound gateway authorization type.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
mcp.outbound_auth_type	1.0.0	STRING	Provider-reported target credential-provider type without credentials.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
mcp.private_endpoint	1.0.0	BOOLEAN	Provider-reported private endpoint presence for MCP configuration.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
mcp.last_synchronized_at	1.0.0	STRING	Provider-reported last successful MCP target synchronization time.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.852509+05:30
agcf.agcf-aws-007.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-007.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-008.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-008.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
resource.status_observed	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-010.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-011.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-011.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
guardrail.content_filter_count_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-012.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-013.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-013.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-014.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-014.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-015.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-015.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-016.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-016.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-017.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-017.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
data.source_count_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-020.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-021.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-021.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-022.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-022.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-023.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-023.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-024.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-024.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-025.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-025.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-026.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-026.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-028.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-028.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-034.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-034.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-035.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-035.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-aws-037.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AWS-037.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
logging.diagnostic_destination_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-006.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
resource.provisioning_state_observed	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-007.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
owner.owner_tag_present_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-008.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-009.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-009.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
guardrail.rai_filter_count_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-011.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-013.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-013.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-014.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-014.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-015.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-015.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-016.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-016.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agent.model_deployment_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-018.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-020.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-020.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-021.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-021.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-023.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-023.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-024.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-024.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
identity.managed_identity_assigned_configured	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-028.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-029.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-029.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-030.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-030.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-031.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-031.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-azr-032.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-AZR-032.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-001.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-001.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-002.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-002.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-003.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-003.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-004.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-004.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-005.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-005.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
agcf.agcf-xsp-006.evidence	1.0.0	BOOLEAN	Phase 1 evidence for AGCF-XSP-006.	["CONFIGURATION", "GRAPH_ANALYSIS"]	["POSTURE_FINDING", "VALIDATED_EXPOSURE"]	86400	ACTIVE	2026-09-03 07:14:18.868808+05:30
mcp.external_or_unapproved_verified	1.0.0	BOOLEAN	Approved graph or runtime evidence verifies that an MCP endpoint is external or unapproved.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.881483+05:30
mcp.auth_inadequate_verified	1.0.0	BOOLEAN	Approved graph or runtime evidence verifies inadequate authentication for an MCP target.	["GRAPH_ANALYSIS", "ACTIVE_TEST", "RUNTIME_OBSERVATION"]	["VALIDATED_EXPOSURE"]	3600	ACTIVE	2026-09-03 07:14:18.881483+05:30
agent.tool_type_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
bot.channel_type_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
compute.instance_type_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
compute.lambda_target_arn_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
data.deletion_policy_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.contextual_grounding_filter_count_configured	1.0.0	NUMBER	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.denied_topic_count_configured	1.0.0	NUMBER	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.pii_entity_count_configured	1.0.0	NUMBER	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.rai_base_policy_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.rai_custom_blocklist_count_configured	1.0.0	NUMBER	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.rai_mode_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
guardrail.updated_at_observed	1.0.0	TIMESTAMP	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
identity.assignment_condition_version_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
identity.assignment_scope_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
identity.principal_type_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
mcp.server_hostname_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
mcp.target_subtype_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
ml.endpoint_traffic_configured	1.0.0	OBJECT	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
ml.model_reference_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.foundation_identifier_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.name_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.provider_name_observed	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.publisher_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.version_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
model.version_upgrade_option_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
network.vpc_id_configured	1.0.0	STRING	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
resource.required_tags_present_configured	1.0.0	BOOLEAN	Canonical provider-observed Phase 1 evidence.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.908858+05:30
identity.effective_access_exceeds_approved_matrix	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.effective_access_exceeds_approved_matrix.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.cross_account_sensitive_access_observed	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.cross_account_sensitive_access_observed.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.unapproved_privileged_role_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.unapproved_privileged_role_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.restriction_controls_incomplete	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.restriction_controls_incomplete.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_effective_block_public_access_incomplete	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_effective_block_public_access_incomplete.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_default_encryption_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_default_encryption_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_customer_managed_key_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_customer_managed_key_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_unapproved_cross_account_principal	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_unapproved_cross_account_principal.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_tls_enforced	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_tls_enforced.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.vector_store_public_network_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.vector_store_public_network_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.vector_store_encryption_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.vector_store_encryption_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.vector_store_principal_boundary_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.vector_store_principal_boundary_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.bedrock_budget_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.bedrock_budget_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.bedrock_quota_alarm_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.bedrock_quota_alarm_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.bedrock_quota_utilization_exceeds_threshold	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.bedrock_quota_utilization_exceeds_threshold.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.bedrock_throttling_alarm_effective	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.bedrock_throttling_alarm_effective.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.bedrock_usage_exceeds_threshold	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.bedrock_usage_exceeds_threshold.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.model_signature_attestation_present	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.model_signature_attestation_present.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.model_approved_registry_lineage	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.model_approved_registry_lineage.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.model_sbom_coverage_present	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.model_sbom_coverage_present.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.model_vulnerability_baseline_pass	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.model_vulnerability_baseline_pass.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.dataset_version_checksum_pinned	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.dataset_version_checksum_pinned.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.dataset_lineage_present	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.dataset_lineage_present.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.dataset_changed_after_approval	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.dataset_changed_after_approval.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.endpoint_public_without_adequate_auth	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.endpoint_public_without_adequate_auth.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.endpoint_tls_baseline_pass	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.endpoint_tls_baseline_pass.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.sagemaker_network_isolation_enabled	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.sagemaker_network_isolation_enabled.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.sagemaker_storage_customer_managed_key	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.sagemaker_storage_customer_managed_key.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.sagemaker_root_access_enabled	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.sagemaker_root_access_enabled.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.sagemaker_image_baseline_pass	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.sagemaker_image_baseline_pass.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.sensitive_access_outside_approved_scope	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.sensitive_access_outside_approved_scope.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.can_elevate_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.can_elevate_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.high_impact_wildcard_permission	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.high_impact_wildcard_permission.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.role_assignment_stale	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.role_assignment_stale.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.pim_activation_required_missing	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.pim_activation_required_missing.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.access_review_missing_or_stale	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.access_review_missing_or_stale.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.data_source_secret_authentication	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.data_source_secret_authentication.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.connection_customer_managed_key	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.connection_customer_managed_key.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.permission_filtering_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.permission_filtering_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.document_authorization_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.document_authorization_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.tenant_partitioning_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.tenant_partitioning_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.retrieval_mode_approved	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.retrieval_mode_approved.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.encryption_customer_managed_key	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.encryption_customer_managed_key.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
search.outbound_shared_private_link_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for search.outbound_shared_private_link_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.storage_public_blob_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.storage_public_blob_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.storage_shared_key_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.storage_shared_key_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.storage_secure_transfer_tls_baseline	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.storage_secure_transfer_tls_baseline.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.storage_customer_managed_key	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.storage_customer_managed_key.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.storage_private_network_boundary	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.storage_private_network_boundary.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.azure_budget_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.azure_budget_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.azure_quota_alert_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.azure_quota_alert_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.azure_quota_utilization_exceeds_threshold	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.azure_quota_utilization_exceeds_threshold.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.azure_throttling_capacity_exceeds_threshold	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.azure_throttling_capacity_exceeds_threshold.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
consumption.azure_usage_exceeds_threshold	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for consumption.azure_usage_exceeds_threshold.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.deployment_image_vulnerability_baseline_pass	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.deployment_image_vulnerability_baseline_pass.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
provenance.mlflow_dataset_lineage_present	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for provenance.mlflow_dataset_lineage_present.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.azure_ml_managed_network_enabled	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.azure_ml_managed_network_enabled.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
model.azure_ml_outbound_egress_restricted	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for model.azure_ml_outbound_egress_restricted.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.bot_public_without_strong_auth	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.bot_public_without_strong_auth.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.bot_managed_identity_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.bot_managed_identity_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.bot_tls_baseline_pass	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.bot_tls_baseline_pass.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.foundry_private_endpoint_configured	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.foundry_private_endpoint_configured.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_effective_public_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_effective_public_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.s3_effective_public_content_access	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.s3_effective_public_content_access.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.inbound_auth_authoritative	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.inbound_auth_authoritative.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.outbound_auth_authoritative	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.outbound_auth_authoritative.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
network.effective_public_network_exposure	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for network.effective_public_network_exposure.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
network.effective_private_endpoint_requirement	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for network.effective_private_endpoint_requirement.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
mcp.foundry_auth_authoritative	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for mcp.foundry_auth_authoritative.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.effective_privileged_scope	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.effective_privileged_scope.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
identity.effective_role_constraints	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for identity.effective_role_constraints.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
data.authoritative_sensitivity_state	1.0.0	BOOLEAN	Canonical Phase 2 provider evidence for data.authoritative_sensitivity_state.	["CONFIGURATION"]	["POSTURE_FINDING"]	86400	ACTIVE	2026-09-03 07:14:18.968589+05:30
\.


--
-- Data for Name: ai_grid_policy_versions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_policy_versions (policy_id, version, name, description, severity, lifecycle, workflow_class, default_selection, artifact_types_json, required_capabilities_json, required_relationships_json, required_resource_families_json, required_facts_json, predicate_json, reason_code, remediation, framework_mappings_json, approved_by, approved_at, published_at, created_at, native_kinds_json, scope_resolution, package_digest, package_source_ref, authored_by, release_notes, replaces_policy_id, replaces_version, parameter_definitions_json, control_objective_id, provider, evaluation_mode, evaluation_definition_json, base_evidence_tiers_json, conditional_capabilities_json, certification_parameter_profile_json, release_family, release_wave) FROM stdin;
AWS_BEDROCK_WEAK_GUARDRAIL	2.0.0	Weak attached guardrail content filters	An attached Bedrock guardrail is configured below the approved minimum strength.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	["AI_AGENT"]	[]	["USES_GUARDRAIL"]	["BEDROCK_AGENTS", "BEDROCK_GUARDRAILS"]	[{"factKey": "bedrock.agent.guardrail_attached_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "bedrock.guardrail.minimum_strength_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"all": [{"eq": true, "fact": "bedrock.agent.guardrail_attached_configured"}, {"fact": "bedrock.guardrail.minimum_strength_configured", "strength_lt": {"parameter": "minimumGuardrailStrength"}}]}	BEDROCK_GUARDRAIL_BELOW_APPROVED_STRENGTH	Configure at least MEDIUM input and output strength for required harmful-content categories.	{"OWASP_LLM_TOP_10": ["LLM01"]}	\N	\N	\N	2026-09-03 07:14:18.788519+05:30	["AWS_BEDROCK_AGENT"]	STATIC	2f9d460804cfdf4008e261f1115e3db1	\N	ai-grid-bootstrap	\N	\N	\N	[{"key": "minimumGuardrailStrength", "type": "ENUM", "options": ["NONE", "LOW", "MEDIUM", "HIGH"], "defaultValue": "MEDIUM"}]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED	2.0.0	Foundry agent Code Interpreter enabled	A Foundry agent enables Code Interpreter.	HIGH	VALIDATED	POSTURE_FINDING	PREVIEW	["AI_AGENT"]	[]	[]	[]	[{"factKey": "agent.code_interpreter_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "agent.code_interpreter_enabled_configured"}	AZURE_FOUNDRY_CODE_INTERPRETER_ENABLED	Disable Code Interpreter unless explicitly approved.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_FOUNDRY_AGENTS"]	NATIVE_KIND_PLUS_STATIC	ce7024c2b1f91149492dfd86a25e2a8f	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED	2.0.0	Azure ML endpoint local authentication enabled	An Azure ML endpoint permits local key authentication.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "identity.ml_endpoint_local_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.ml_endpoint_local_auth_enabled_configured"}	AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED	Require Microsoft Entra authentication.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_ML_ENDPOINTS"]	NATIVE_KIND_PLUS_STATIC	cf7714fba390d951fec3a1ebdb1c9e57	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_RAI_POLICY_NON_BLOCKING_FILTER	1.0.0	Azure RAI policy contains a non-blocking filter	An Azure RAI policy explicitly disables a returned content filter or configures it as non-blocking.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["AI_GUARDRAIL"]	[]	[]	["AZURE_RAI_POLICIES"]	[{"factKey": "guardrail.rai_non_blocking_filter_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "guardrail.rai_non_blocking_filter_observed"}	AZURE_RAI_FILTER_DISABLED_OR_NON_BLOCKING	Enable blocking for every explicitly configured RAI content filter. Review category and threshold completeness separately.	{"OWASP_LLM_TOP_10": ["LLM01", "LLM09"]}	\N	\N	\N	2026-09-03 07:14:18.82034+05:30	["AZURE_RAI_POLICIES"]	STATIC	9584fb77f0162cbee12dcc61273ca9ae	\N	ai-grid-r1-azure-rai-slice	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH	2.0.0	Azure AI Search data source does not use identity authentication	Search data-source authentication is not identity based.	HIGH	VALIDATED	POSTURE_FINDING	PREVIEW	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "identity.search_data_source_non_identity_auth_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.search_data_source_non_identity_auth_observed"}	AZURE_SEARCH_NON_IDENTITY_AUTH	Use a managed identity for the Search data-source connection.	{"OWASP_LLM_TOP_10": ["LLM06", "LLM08"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_SEARCH_DATA_SOURCES"]	NATIVE_KIND_PLUS_STATIC	3014546ad8b0fdd8a98fda6261f1ec2f	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED	2.0.0	Azure AI Search local admin authentication enabled	An Azure AI Search service permits local admin-key authentication.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "identity.search_local_admin_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.search_local_admin_auth_enabled_configured"}	AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED	Disable local authentication and use Entra RBAC.	{"OWASP_LLM_TOP_10": ["LLM06", "LLM08"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_SEARCH_SERVICES"]	NATIVE_KIND_PLUS_STATIC	63df32caa0f880fdf12b4e84f7c132c7	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL	1.0.0	MCP target unhealthy or synchronization unsuccessful	A provider-managed MCP target reports a failed terminal or unsuccessful synchronization state.	MEDIUM	VALIDATED	POSTURE_FINDING	PREVIEW	["MCP_TARGET"]	[]	[]	["AWS_AGENTCORE_GATEWAY_TARGETS"]	[{"factKey": "mcp.target_status", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "UPDATE_UNSUCCESSFUL", "SYNCHRONIZE_UNSUCCESSFUL"], "fact": "mcp.target_status"}	MCP_TARGET_UNHEALTHY	Repair the target configuration and confirm a successful provider synchronization.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.850569+05:30	[]	STATIC	a67ef72322825e758a215300e90484a4	\N	\N	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_AI_CUSTOMER_MANAGED_KEY_MISSING	1.0.0	Azure AI customer-managed-key encryption missing	The Azure AI account is not configured with a customer-managed encryption key.	MEDIUM	VALIDATED	POSTURE_FINDING	ENABLED	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "data.customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "data.customer_managed_key_configured"}	AZURE_AI_CUSTOMER_MANAGED_KEY_MISSING	Configure encryption with a customer-managed key in an approved Key Vault.	{"OWASP_LLM_TOP_10": ["LLM02", "LLM03"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_AI_ACCOUNTS"]	NATIVE_KIND_PLUS_STATIC	fd8eb12b93a2f61ca739e1c4a641bc6b	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH	1.0.0	Public MCP endpoint without configured authentication	A provider explicitly confirms public network reachability and reports no configured authentication; an external URL alone yields no decision.	CRITICAL	VALIDATED	POSTURE_FINDING	PREVIEW	["MCP_SERVER"]	[]	[]	[]	[{"factKey": "mcp.endpoint_exposure", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "mcp.configured_auth_type", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"all": [{"eq": "PUBLIC_NETWORK_REACHABLE", "fact": "mcp.endpoint_exposure"}, {"eq": "NONE", "fact": "mcp.configured_auth_type"}]}	MCP_PUBLIC_ENDPOINT_NO_AUTH	Configure an approved authentication mechanism before exposing the MCP endpoint.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.850569+05:30	[]	STATIC	0efb8ddfa47f10a907fd4123937ff5ef	\N	\N	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_AI_LOCAL_AUTH_ENABLED	2.0.0	Azure AI local authentication enabled	An Azure AI account permits key-based local authentication.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "identity.local_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.local_auth_enabled_configured"}	AZURE_AI_LOCAL_AUTH_ENABLED	Disable local authentication and require Microsoft Entra identities.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_AI_ACCOUNTS"]	NATIVE_KIND_PLUS_STATIC	b4b2d41d64666f299a6293622c3f8487	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_AI_PRIVATE_ENDPOINT_MISSING	1.0.0	Azure AI private endpoint missing	No private endpoint connection is configured for the managed AI resource.	MEDIUM	VALIDATED	POSTURE_FINDING	PREVIEW	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "network.private_endpoint_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": 0, "fact": "network.private_endpoint_count_configured"}	AZURE_AI_PRIVATE_ENDPOINT_MISSING	Configure an approved private endpoint and restrict public network access.	{"OWASP_LLM_TOP_10": ["LLM02"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_AI_ACCOUNTS"]	NATIVE_KIND_PLUS_STATIC	fa0c0a367b21a8a1ce01363e2dc4bc51	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS	2.0.0	Unrestricted Azure AI public access	A managed Azure AI resource permits unrestricted public network access.	CRITICAL	VALIDATED	POSTURE_FINDING	REQUIRED	["OTHER_AI_ARTIFACT"]	[]	[]	[]	[{"factKey": "network.public_access_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "network.public_access_configured"}	AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS	Disable public access or restrict network ACLs and use approved private endpoints.	{"OWASP_LLM_TOP_10": ["LLM02", "LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_AI_ACCOUNTS", "AZURE_ML_WORKSPACES", "AZURE_SEARCH_SERVICES"]	NATIVE_KIND_PLUS_STATIC	54de9ccf6d1a101d38676699602d9cc6	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY	2.0.0	Azure Bot password authentication without managed identity	An Azure Bot uses password authentication without a managed identity.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["AI_AGENT"]	[]	[]	["AZURE_BOT_IDENTITIES"]	[{"factKey": "identity.bot_password_without_managed_identity_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.bot_password_without_managed_identity_observed"}	AZURE_BOT_PASSWORD_WITHOUT_MANAGED_IDENTITY	Assign a managed identity and remove password credentials.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_BOT_SERVICES"]	STATIC	a5609c0623f73befac99daf1a267cd0a	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AWS_BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING	1.0.0	Bedrock agent inactive or missing execution role	The agent is not prepared or has no configured execution role.	MEDIUM	VALIDATED	POSTURE_FINDING	PREVIEW	["AI_AGENT"]	[]	[]	["BEDROCK_AGENTS"]	[{"factKey": "agent.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "identity.execution_role_present_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"neq": "PREPARED", "fact": "agent.status_observed"}, {"eq": false, "fact": "identity.execution_role_present_configured"}]}	BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING	Prepare the agent and configure its least-privileged execution role.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_AGENT"]	STATIC	caaf28356ee65d5ce97f56323c95176b	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AGCF-AWS-010	1.0.0	Bedrock guardrail is failed, deleting, or otherwise non-active	Detects when bedrock guardrail is failed, deleting, or otherwise non-active using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "DELETING", "INACTIVE"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_010	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	2085139054fde1a89dd39349c5246be8659b3f86e16e5df8bd2c879da5d4c02e	policy-packages/agcf/AGCF-AWS-010/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-010	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "DELETING", "INACTIVE"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED	2.0.0	Azure AI diagnostic logging disabled	An Azure AI account has no enabled diagnostic-log destination.	MEDIUM	VALIDATED	POSTURE_FINDING	ENABLED	["OTHER_AI_ARTIFACT"]	[]	[]	["AZURE_DIAGNOSTIC_SETTINGS"]	[{"factKey": "logging.diagnostic_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "logging.diagnostic_enabled_configured"}	AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED	Enable diagnostic logs to an approved destination.	{"OWASP_LLM_TOP_10": ["LLM02"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AZURE_AI_ACCOUNTS"]	NATIVE_KIND_PLUS_STATIC	20879ad8aca6cf6762aadb077e73e85b	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS	1.0.0	Sensitive AI data source with public content access	A provider-confirmed sensitive data store is also provider-confirmed to allow public content access.	CRITICAL	VALIDATED	POSTURE_FINDING	PREVIEW	["DATA_STORE"]	[]	[]	["AWS_MACIE_PII", "S3_EXPOSURE"]	[{"factKey": "data.sensitivity_confirmed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "data.public_content_access_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"all": [{"eq": true, "fact": "data.sensitivity_confirmed"}, {"eq": true, "fact": "data.public_content_access_configured"}]}	SENSITIVE_DATA_PUBLIC_CONTENT	Restrict content access and verify the data-store policy no longer allows public reads.	{"OWASP_LLM_TOP_10": ["LLM02"]}	\N	\N	\N	2026-09-03 07:14:18.850569+05:30	[]	STATIC	7afe27744b9d03b3de4e678496a8e045	\N	\N	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AGCF-XSP-005	1.0.0	Agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth	Detects when agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_005	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	c91296a7958e37a3d29f78d08304b5310d06f9cb8883ef35851e2b44da4d75bc	policy-packages/agcf/AGCF-XSP-005/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-005	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_MCP_WEAK_AUTH_EXECUTION", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-010	1.0.0	Azure RAI policy explicitly disables or does not block a returned filter	Detects when azure RAI policy explicitly disables or does not block a returned filter using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["FOUNDRY_DEPLOYMENTS_RAI"]	[]	[]	[{"factKey": "guardrail.rai_non_blocking_filter_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "guardrail.rai_non_blocking_filter_observed"}	AGCF_AGCF_AZR_010	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM10", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "AIS-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	a54b33061982f59777b5aa68c4ed9f7b06b960eaf56eee683e4afe5e317c5dea	policy-packages/agcf/AGCF-AZR-010/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-010	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "guardrail.rai_non_blocking_filter_observed"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AWS_BEDROCK_GUARDRAIL_NOT_ATTACHED	1.0.0	No guardrail attached to Bedrock agent	A Bedrock agent has no configured guardrail association.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["AI_AGENT"]	[]	[]	["BEDROCK_AGENTS"]	[{"factKey": "bedrock.agent.guardrail_attached_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "bedrock.agent.guardrail_attached_configured"}	BEDROCK_GUARDRAIL_NOT_ATTACHED	Attach an approved Bedrock guardrail to every production agent path.	{"OWASP_LLM_TOP_10": ["LLM01", "LLM05"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_AGENT"]	STATIC	e5e735b701d20b7dc97570e3f2aa3b64	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AWS_BEDROCK_INVOCATION_LOGGING_DISABLED	2.0.0	Bedrock invocation logging disabled	Model invocation logging is disabled.	MEDIUM	VALIDATED	POSTURE_FINDING	ENABLED	["ACCOUNT_CONFIGURATION"]	[]	[]	["BEDROCK_INVOCATION_LOGGING"]	[{"factKey": "logging.model_invocation_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "logging.model_invocation_enabled_configured"}	BEDROCK_INVOCATION_LOGGING_DISABLED	Enable encrypted Bedrock model invocation logging.	{"OWASP_LLM_TOP_10": ["LLM02"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_INVOCATION_LOGGING"]	STATIC	18500ea122fc0bff48d40631da72a639	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AWS_BEDROCK_PUBLIC_KB_S3	2.0.0	Public knowledge-base S3 source	A Bedrock knowledge base uses a publicly accessible S3 source.	CRITICAL	VALIDATED	POSTURE_FINDING	REQUIRED	["KNOWLEDGE_BASE"]	[]	[]	["BEDROCK_KNOWLEDGE_BASES", "S3_EXPOSURE"]	[{"factKey": "data.s3_public_access_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_public_access_configured"}	BEDROCK_KB_S3_PUBLIC	Block public access and restrict the bucket policy to the knowledge-base execution role.	{"OWASP_LLM_TOP_10": ["LLM02", "LLM08"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_KNOWLEDGE_BASE"]	STATIC	155b5eff823183e5d76d0ef928f4f3c0	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AWS_BEDROCK_UNAUTH_LAMBDA_URL	2.0.0	Unauthenticated action-group Lambda URL	An agent action group exposes a Lambda URL without IAM authentication.	CRITICAL	VALIDATED	POSTURE_FINDING	REQUIRED	["AI_AGENT"]	[]	[]	["BEDROCK_AGENTS", "LAMBDA_URLS"]	[{"factKey": "compute.lambda_url_auth_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": "NONE", "fact": "compute.lambda_url_auth_type_configured"}	BEDROCK_LAMBDA_URL_UNAUTHENTICATED	Require AWS_IAM authentication or remove the function URL.	{"OWASP_LLM_TOP_10": ["LLM06"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_AGENT"]	STATIC	665b4283e3dae5cbc8b47d04bb67a8f5	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AWS_BEDROCK_WILDCARD_AGENT_ROLE	2.0.0	Wildcard agent execution-role actions	A syntactic wildcard action was observed in the agent execution role.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	["AI_AGENT"]	[]	[]	["BEDROCK_AGENTS", "IAM_GLOBAL"]	[{"factKey": "identity.wildcard_permission_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.wildcard_permission_observed"}	BEDROCK_AGENT_ROLE_WILDCARD	Replace wildcard actions with minimum required actions and resources.	{"OWASP_LLM_TOP_10": ["LLM06", "LLM08"]}	\N	\N	\N	2026-09-03 07:14:18.794726+05:30	["AWS_BEDROCK_AGENT"]	STATIC	3f262b26aeb6fadf876bbfe7a3a0fa76	\N	ai-grid-r1-bootstrap	\N	\N	\N	[]	\N	\N	\N	\N	[]	[]	\N	\N	\N
AGCF-XSP-002	1.0.0	Code Interpreter or another high-impact tool has a direct path to confirmed sensitive data	Detects when code Interpreter or another high-impact tool has a direct path to confirmed sensitive data using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_002	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "AIS-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	c5924043d588c67f2031ac30ebe4df12f9b569ed35815fd3f8bc3f2e9e687fc2	policy-packages/agcf/AGCF-XSP-002/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-002	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_UNTRUSTED_AUTONOMOUS_EXECUTION", "correlationVersion": "1.0.0"}}	["E2"]	["MACIE_CLASSIFICATION", "PURVIEW_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-XSP-003	1.0.0	Wildcard or broad identity permissions reach a high-impact agent tool	Detects when wildcard or broad identity permissions reach a high-impact agent tool using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_003	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	dc97f04ed54742f22c6508c48895137b030a4dbcd5bd1b9ba62ee841b53876db	policy-packages/agcf/AGCF-XSP-003/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-003	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_EXCESSIVE_TOOL_PRIVILEGE", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-XSP-004	1.0.0	External or unapproved MCP server is reachable from an agent that can access sensitive data	Detects when external or unapproved MCP server is reachable from an agent that can access sensitive data using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_004	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	10d8195e99d426cfd7e7de6205af391fb95aed50c2136efeacf4ac6054be909d	policy-packages/agcf/AGCF-XSP-004/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-004	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_EXTERNAL_MCP_SENSITIVE_ACCESS", "correlationVersion": "1.0.0"}}	["E2"]	["MACIE_CLASSIFICATION", "PURVIEW_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-002	1.0.0	Attached Bedrock guardrail is below the configured minimum strength	Detects when attached Bedrock guardrail is below the configured minimum strength using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "bedrock.guardrail.minimum_strength_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "bedrock.guardrail.minimum_strength_configured", "strength_lt": "HIGH"}	AGCF_AGCF_AWS_002	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	c12b96252a146d3e49dfb137130bf02888d2aafd01490fb94cf97f72e30b6a2a	policy-packages/agcf/AGCF-AWS-002/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-002	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "bedrock.guardrail.minimum_strength_configured", "strength_lt": "HIGH"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-001	1.0.0	Bedrock agent has no guardrail attached	Detects when bedrock agent has no guardrail attached using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "bedrock.agent.guardrail_attached_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "bedrock.agent.guardrail_attached_configured"}	AGCF_AGCF_AWS_001	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	57781735b507f8f284472af507020181380e71ae41716fd70ba84a904e2697b1	policy-packages/agcf/AGCF-AWS-001/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-001	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "bedrock.agent.guardrail_attached_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-018	1.0.0	Bedrock knowledge base is failed or unavailable	Detects when bedrock knowledge base is failed or unavailable using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_KNOWLEDGE_BASES"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "DELETE_UNSUCCESSFUL", "UNAVAILABLE"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_018	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "INFORMATIVE", "frameworkVersion": "2026"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "BCR-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	33027bed112f7fb9e19f2f532c04a7996dc105c76b9aa931e859d72aa797b927	policy-packages/agcf/AGCF-AWS-018/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-018	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "DELETE_UNSUCCESSFUL", "UNAVAILABLE"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-012	1.0.0	Foundry deployment has no RAI policy reference	Detects when foundry deployment has no RAI policy reference using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["FOUNDRY_DEPLOYMENTS_RAI"]	[]	[]	[{"factKey": "guardrail.rai_policy_reference_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.rai_policy_reference_configured", "empty": true}	AGCF_AGCF_AZR_012	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM10", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "CCC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	664aca53cd6c3ed7f437dfa42cca2372280a3066797a9a4fba7c98c8cd45f79a	policy-packages/agcf/AGCF-AZR-012/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-012	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.rai_policy_reference_configured", "empty": true}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-022	1.0.0	Azure ML online endpoint permits local/key authentication	Detects when azure ML online endpoint permits local/key authentication using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["ML_WORKSPACES_ENDPOINTS"]	[]	[]	[{"factKey": "identity.ml_endpoint_local_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.ml_endpoint_local_auth_enabled_configured"}	AGCF_AGCF_AZR_022	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	5ed0d2f2958c4c71f29e16601ef01bebf77ae8905f0f42954c64d0025d832108	policy-packages/agcf/AGCF-AZR-022/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-022	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.ml_endpoint_local_auth_enabled_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-003	1.0.0	Bedrock agent is not in an approved operational state	Detects when bedrock agent is not in an approved operational state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "agent.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "DELETING", "PREPARE_FAILED"], "fact": "agent.status_observed"}	AGCF_AGCF_AWS_003	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "INFORMATIVE", "frameworkVersion": "2026"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	9feb9672faee1c0cbac3301be20f69bfde67b30cd8373932260fe36404e32487	policy-packages/agcf/AGCF-AWS-003/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-003	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "DELETING", "PREPARE_FAILED"], "fact": "agent.status_observed"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-004	1.0.0	Bedrock agent execution role is missing	Detects when bedrock agent execution role is missing using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_AGENTS", "IAM_ROLE_POLICIES"]	[]	[]	[{"factKey": "identity.execution_role_present_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "identity.execution_role_present_configured"}	AGCF_AGCF_AWS_004	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	07cd28465e7064470b624fb880f668fb85d1378748ecc5c7170e84a4f342d09f	policy-packages/agcf/AGCF-AWS-004/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-004	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "identity.execution_role_present_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-032	1.0.0	AI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification	Detects when aI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "data.source_sensitivity", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["NOT_SCANNED"], "fact": "data.source_sensitivity"}	AGCF_AGCF_AZR_032	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-04", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_STORAGE_ACCOUNTS", "AZURE_ONELAKE_STORES"]	STATIC	0f05267df3a5c72b4210721794a71b91560e321c3bce4c12926cad6aed51e62c	policy-packages/agcf/AGCF-AZR-032/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-032	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["NOT_SCANNED"], "fact": "data.source_sensitivity"}}}	["E0"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-005	1.0.0	Bedrock execution role contains wildcard actions	Detects when bedrock execution role contains wildcard actions using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_AGENTS", "IAM_ROLE_POLICIES"]	[]	[]	[{"factKey": "identity.wildcard_permission_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.wildcard_permission_observed"}	AGCF_AGCF_AWS_005	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	23b8b88e1f39b1027b06523d80f50a0d04c561a70c20892935f3de39f08c590d	policy-packages/agcf/AGCF-AWS-005/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-005	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.wildcard_permission_observed"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-053	1.0.0	Azure AI consumption budget is absent	Evaluates whether azure ai consumption budget is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.azure_budget_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.azure_budget_configured"}	AGCF_P2_AZURE_053	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AZURE COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	8b7e98a5a1ffbbe0a5c5cce0e416eccdcd0a3e821f5aee4ab19f86773c816ded	policy-packages/agcf/AGCF-AZR-053/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-053	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.azure_budget_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-006	1.0.0	Action-group Lambda URL permits unauthenticated invocation	Detects when action-group Lambda URL permits unauthenticated invocation using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["LAMBDA_URLS"]	[]	[]	[{"factKey": "compute.lambda_url_auth_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": "NONE", "fact": "compute.lambda_url_auth_type_configured"}	AGCF_AGCF_AWS_006	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	7bb3c448e05ef599a309356a41c30bbd6840754861453cf7cf1919d61d121c2d	policy-packages/agcf/AGCF-AWS-006/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-006	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": "NONE", "fact": "compute.lambda_url_auth_type_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-007	1.0.0	Agent foundation model is outside the tenant-approved allowlist	Detects when agent foundation model is outside the tenant-approved allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "model.foundation_identifier_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedFoundationModels"}, "fact": "model.foundation_identifier_configured"}}	AGCF_AGCF_AWS_007	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "STA-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-12", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_AGENT"]	STATIC	5c190b1ba579381d98752ed9bfe778ee72726f322a33ea9ae746ae4d2c666586	policy-packages/agcf/AGCF-AWS-007/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedFoundationModels", "type": "STRING_LIST", "defaultValue": ["amazon.nova-pro-v1:0"]}]	AGCF-OBJ-AWS-007	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedFoundationModels"}, "fact": "model.foundation_identifier_configured"}}}}	["E1"]	[]	{"fail": {"approvedFoundationModels": []}, "pass": {"approvedFoundationModels": ["amazon.nova-pro-v1:0"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-008	1.0.0	Agent action-group Lambda target is outside the approved target allowlist	Detects when agent action-group Lambda target is outside the approved target allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["LAMBDA_URLS"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[{"factKey": "compute.lambda_target_arn_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedLambdaTargets"}, "fact": "compute.lambda_target_arn_configured"}}	AGCF_AGCF_AWS_008	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_LAMBDA_FUNCTION"]	STATIC	a1ca007efa0d57ff15657a8c0f5e319cf29e3594083f7b25ff53f1305652ee67	policy-packages/agcf/AGCF-AWS-008/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedLambdaTargets", "type": "STRING_LIST", "defaultValue": []}]	AGCF-OBJ-AWS-008	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedLambdaTargets"}, "fact": "compute.lambda_target_arn_configured"}}}}	["E2"]	[]	{"fail": {"approvedLambdaTargets": ["CERTIFICATION_APPROVED_VALUE"]}, "pass": {"approvedLambdaTargets": []}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-009	1.0.0	Bedrock model invocation logging is disabled	Detects when bedrock model invocation logging is disabled using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "logging.model_invocation_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "logging.model_invocation_enabled_configured"}	AGCF_AGCF_AWS_009	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-07", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "LOG-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "LOG-16", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	b0e9bd0238a1a76adb5962d9a50752c9d00df4c753b351ebcf37123500f79a6c	policy-packages/agcf/AGCF-AWS-009/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-009	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "logging.model_invocation_enabled_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-011	1.0.0	Bedrock guardrail lacks a customer-managed KMS key where CMK is required	Detects when bedrock guardrail lacks a customer-managed KMS key where CMK is required using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "data.customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "data.customer_managed_key_configured"}	AGCF_AGCF_AWS_011	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "CEK-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "CEK-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_GUARDRAIL"]	STATIC	9ca94d96b62255aff0b50627bce8a40a93b8958b1a28868c29eab35127d480da	policy-packages/agcf/AGCF-AWS-011/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AWS-011	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "data.customer_managed_key_configured"}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-012	1.0.0	Bedrock guardrail has no configured content filters	Detects when bedrock guardrail has no configured content filters using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "guardrail.content_filter_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.content_filter_count_configured", "count_eq": 0}	AGCF_AGCF_AWS_012	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM10", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "AIS-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	07cc0a7ce59e1691a3b05fb5b35ef25533a91dda201a96423108429edbea5d40	policy-packages/agcf/AGCF-AWS-012/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-012	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.content_filter_count_configured", "count_eq": 0}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-013	1.0.0	Sensitive-data agent lacks configured PII guardrail entities	Detects when sensitive-data agent lacks configured PII guardrail entities using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "guardrail.pii_entity_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.pii_entity_count_configured", "count_eq": 0}	AGCF_AGCF_AWS_013	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_GUARDRAIL"]	STATIC	ad4f6868de61f569dc70460d3c146a948aee1191c660cc189800d546f02cdd3c	policy-packages/agcf/AGCF-AWS-013/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-013	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.pii_entity_count_configured", "count_eq": 0}}}	["E1"]	["MACIE_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-014	1.0.0	Grounded-generation baseline requires contextual grounding filters, but none are configured	Detects when grounded-generation baseline requires contextual grounding filters, but none are configured using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "guardrail.contextual_grounding_filter_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.contextual_grounding_filter_count_configured", "count_eq": 0}	AGCF_AGCF_AWS_014	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM07", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "GRC-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_GUARDRAIL"]	STATIC	7dcf639821e689065acde25d6ee6e641b80e01eb473f03b6d4ef11ae65b623c0	policy-packages/agcf/AGCF-AWS-014/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AWS-014	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.contextual_grounding_filter_count_configured", "count_eq": 0}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-015	1.0.0	Denied-topic baseline is required, but no denied topics are configured	Detects when denied-topic baseline is required, but no denied topics are configured using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "guardrail.denied_topic_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.denied_topic_count_configured", "count_eq": 0}	AGCF_AGCF_AWS_015	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM07", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "GRC-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_GUARDRAIL"]	STATIC	e9a5a7eed7500f691aec17b5ef623e0e6dfdac7c55c3e54c01f93633c930b84a	policy-packages/agcf/AGCF-AWS-015/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AWS-015	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.denied_topic_count_configured", "count_eq": 0}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-016	1.0.0	Guardrail configuration has not been reviewed within the configured maximum age	Detects when guardrail configuration has not been reviewed within the configured maximum age using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_GUARDRAILS"]	[]	[]	[{"factKey": "guardrail.updated_at_observed", "valueType": "TIMESTAMP", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.updated_at_observed", "age_gt_seconds": {"parameter": "maximumReviewAgeSeconds"}}	AGCF_AGCF_AWS_016	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "INFORMATIVE", "frameworkVersion": "2026"}, {"controlId": "CCC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_GUARDRAIL"]	STATIC	63b237f362088e6e18fe80b313c6a2d0f8cbe1c8b72f7b0d523251097e822d75	policy-packages/agcf/AGCF-AWS-016/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "maximumReviewAgeSeconds", "type": "NUMBER", "defaultValue": 7776000}]	AGCF-OBJ-AWS-016	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.updated_at_observed", "age_gt_seconds": {"parameter": "maximumReviewAgeSeconds"}}}}	["E1"]	[]	{"fail": {"maximumReviewAgeSeconds": 7776001}, "pass": {"maximumReviewAgeSeconds": 7776000}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-017	1.0.0	Bedrock knowledge base uses an S3 source with public policy exposure	Detects when bedrock knowledge base uses an S3 source with public policy exposure using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_KNOWLEDGE_BASES"]	[]	[]	[{"factKey": "data.s3_public_access_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_public_access_configured"}	AGCF_AGCF_AWS_017	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-16", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_KNOWLEDGE_BASE"]	STATIC	92032a2275adb81da31144fba77922b2466e398dece88862760f29b84911c799	policy-packages/agcf/AGCF-AWS-017/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-017	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_public_access_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-XSP-006	1.0.0	Agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline	Detects when agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_006	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-16", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	d7907c4de2724d819152f823c92799c27d7bc977b79bd23fe4f2fa43f41162c1	policy-packages/agcf/AGCF-XSP-006/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-006	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP", "correlationVersion": "1.0.0"}}	["E2"]	["MACIE_CLASSIFICATION", "PURVIEW_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-027	1.0.0	Referenced foundation model lifecycle is not ACTIVE	Detects when referenced foundation model lifecycle is not ACTIVE using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["LEGACY", "DEPRECATED", "RETIRED"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_027	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-12", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	60357eaee299c5f144c7c9979655d44f81fae435acf0b218186aa5045ab4a331	policy-packages/agcf/AGCF-AWS-027/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-027	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["LEGACY", "DEPRECATED", "RETIRED"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-019	1.0.0	Bedrock data source is failed or unavailable	Detects when bedrock data source is failed or unavailable using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_KNOWLEDGE_BASES"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "DELETE_UNSUCCESSFUL", "UNAVAILABLE"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_019	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-20", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-23", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	c8ce30888a018c8442570d5cc4f803285682a6cf8bd81886a30fa13172c7edcd	policy-packages/agcf/AGCF-AWS-019/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-019	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "DELETE_UNSUCCESSFUL", "UNAVAILABLE"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-020	1.0.0	Bedrock data-source configuration is absent	Detects when bedrock data-source configuration is absent using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "data.source_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "data.source_count_configured", "count_eq": 0}	AGCF_AGCF_AWS_020	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-05", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	5600cba4b91ce8eb887aa61252cd19620274a3818f3df6ac9c5338b88dde04ed	policy-packages/agcf/AGCF-AWS-020/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-020	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "data.source_count_configured", "count_eq": 0}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-021	1.0.0	Bedrock data-source type is outside the approved source allowlist	Detects when bedrock data-source type is outside the approved source allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "data.source_type", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedSourceTypes"}, "fact": "data.source_type"}}	AGCF_AGCF_AWS_021	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-20", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_DATA_SOURCE"]	STATIC	a2f3b5aa79d35ca337633c73ecb65635ce29f2feba47945ed63449f4408e1391	policy-packages/agcf/AGCF-AWS-021/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedSourceTypes", "type": "STRING_LIST", "defaultValue": ["S3"]}]	AGCF-OBJ-AWS-021	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedSourceTypes"}, "fact": "data.source_type"}}}}	["E1"]	[]	{"fail": {"approvedSourceTypes": []}, "pass": {"approvedSourceTypes": ["S3"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-022	1.0.0	Bedrock data deletion policy violates the tenant retention baseline	Detects when bedrock data deletion policy violates the tenant retention baseline using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "data.deletion_policy_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedDeletionPolicies"}, "fact": "data.deletion_policy_configured"}}	AGCF_AGCF_AWS_022	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-16", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_DATA_SOURCE"]	STATIC	17b466fce5a0933cd2f29a16ba150570968b5bd7bdbb7c100fe9247c53b3effe	policy-packages/agcf/AGCF-AWS-022/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedDeletionPolicies", "type": "STRING_LIST", "defaultValue": ["RETAIN"]}]	AGCF-OBJ-AWS-022	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedDeletionPolicies"}, "fact": "data.deletion_policy_configured"}}}}	["E1"]	[]	{"fail": {"approvedDeletionPolicies": []}, "pass": {"approvedDeletionPolicies": ["RETAIN"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-023	1.0.0	AI data store has unknown, failed, or stale sensitivity classification	Detects when aI data store has unknown, failed, or stale sensitivity classification using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_KNOWLEDGE_BASES"]	[]	[]	[{"factKey": "data.source_sensitivity", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["NOT_SCANNED"], "fact": "data.source_sensitivity"}	AGCF_AGCF_AWS_023	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-04", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_S3_DATA_STORE"]	STATIC	46bd7553eb526bbdc0020e2471c68d8e708897765a5a680e923790778db323b6	policy-packages/agcf/AGCF-AWS-023/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-023	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["NOT_SCANNED"], "fact": "data.source_sensitivity"}}}	["E0"]	["MACIE_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-024	1.0.0	Macie-confirmed sensitive AI data store permits public content access	Detects when macie-confirmed sensitive AI data store permits public content access using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BEDROCK_KNOWLEDGE_BASES"]	[]	[]	[{"factKey": "data.sensitivity_confirmed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "data.source_public_content_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"all": [{"eq": true, "fact": "data.sensitivity_confirmed"}, {"eq": true, "fact": "data.source_public_content_access"}]}	AGCF_AGCF_AWS_024	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_S3_DATA_STORE"]	STATIC	32493d9bac26e8c6392bc9e0be84bb475257836e4b95e8cb3a33b435bd483a69	policy-packages/agcf/AGCF-AWS-024/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-024	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"all": [{"eq": true, "fact": "data.sensitivity_confirmed"}, {"eq": true, "fact": "data.source_public_content_access"}]}}}	["E0"]	["MACIE_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-025	1.0.0	Bedrock custom model lacks a customer-managed KMS key where required	Detects when bedrock custom model lacks a customer-managed KMS key where required using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "data.customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "data.customer_managed_key_configured"}	AGCF_AGCF_AWS_025	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "CEK-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "CEK-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_CUSTOM_MODEL"]	STATIC	8d45578380aee8ad28aa11817b4fac1e767322c216a0c25b859d95bd12910c34	policy-packages/agcf/AGCF-AWS-025/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AWS-025	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "data.customer_managed_key_configured"}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-026	1.0.0	Bedrock imported model lacks a customer-managed KMS key where required	Detects when bedrock imported model lacks a customer-managed KMS key where required using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "data.customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "data.customer_managed_key_configured"}	AGCF_AGCF_AWS_026	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "CEK-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_IMPORTED_MODEL"]	STATIC	00f9dbf74b2df8503837a8d898285bbb83ef77008ef19f449d0f32ab47d81e81	policy-packages/agcf/AGCF-AWS-026/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AWS-026	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "data.customer_managed_key_configured"}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-028	1.0.0	Model provider or model identifier is outside the approved allowlist	Detects when model provider or model identifier is outside the approved allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "model.provider_name_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedModelProviders"}, "fact": "model.provider_name_observed"}}	AGCF_AGCF_AWS_028	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "STA-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_BEDROCK_MODEL"]	STATIC	7790daf45be65ae53c8e236df812d4015709b651405a3103726017662f775153	policy-packages/agcf/AGCF-AWS-028/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedModelProviders", "type": "STRING_LIST", "defaultValue": ["Amazon"]}]	AGCF-OBJ-AWS-028	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedModelProviders"}, "fact": "model.provider_name_observed"}}}}	["E1"]	[]	{"fail": {"approvedModelProviders": []}, "pass": {"approvedModelProviders": ["Amazon"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-029	1.0.0	Bedrock custom/imported model or customization job is in a failed terminal state	Detects when bedrock custom/imported model or customization job is in a failed terminal state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_029	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-01", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	c0591f1280f470e380698f3ad97e4162b314d3eff20988f819d57be51f76e429	policy-packages/agcf/AGCF-AWS-029/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-029	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-030	1.0.0	Provisioned model or inference profile is in an unhealthy state	Detects when provisioned model or inference profile is in an unhealthy state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_MODELS_JOBS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "STOPPED", "UNHEALTHY"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_030	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "I&S-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	136d320464e1b73b69caa7aefebd72e73caf94328c986bc78fc66cf7813a09ae	policy-packages/agcf/AGCF-AWS-030/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-030	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "STOPPED", "UNHEALTHY"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-031	1.0.0	AgentCore gateway inbound authorization is missing or outside the approved auth types	Detects when agentCore gateway inbound authorization is missing or outside the approved auth types using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["AGENTCORE_GATEWAYS_TARGETS"]	[]	[]	[{"factKey": "mcp.inbound_auth_type", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.inbound_auth_type"}	AGCF_AGCF_AWS_031	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	2a234e76ad25868156e3292f6c599149fbefd375585273e6b5d8fc7c2c75fe55	policy-packages/agcf/AGCF-AWS-031/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-031	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.inbound_auth_type"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-032	1.0.0	AgentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types	Detects when agentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["AGENTCORE_GATEWAYS_TARGETS"]	[]	[]	[{"factKey": "mcp.outbound_auth_type", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.outbound_auth_type"}	AGCF_AGCF_AWS_032	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	cd0298bd26d3ae64f730b55da8ccccdcd4a4cdb81ef4913b8e775b1f9f25f202	policy-packages/agcf/AGCF-AWS-032/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-032	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.outbound_auth_type"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-033	1.0.0	AgentCore target is failed, unsynchronized, or stale beyond the configured age	Detects when agentCore target is failed, unsynchronized, or stale beyond the configured age using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["AGENTCORE_GATEWAYS_TARGETS"]	[]	[]	[{"factKey": "mcp.target_status", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "UNSYNCHRONIZED"], "fact": "mcp.target_status"}	AGCF_AGCF_AWS_033	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	9723cada991dc4c9de96f16e50e67fd13b320f5d61294c96a7fa11d45b5fe382	policy-packages/agcf/AGCF-AWS-033/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-033	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "UNSYNCHRONIZED"], "fact": "mcp.target_status"}}}	["E0", "E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-034	1.0.0	MCP target subtype or server hostname is outside the tenant allowlist	Detects when mCP target subtype or server hostname is outside the tenant allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AGENTCORE_GATEWAYS_TARGETS"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[{"factKey": "mcp.target_subtype_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "mcp.server_hostname_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"not": {"in": {"parameter": "approvedMcpTargetSubtypes"}, "fact": "mcp.target_subtype_configured"}}, {"not": {"in": {"parameter": "approvedMcpServerHosts"}, "fact": "mcp.server_hostname_configured"}}]}	AGCF_AGCF_AWS_034	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_AGENTCORE_GATEWAY_TARGET", "AWS_AGENTCORE_MCP_SERVER"]	STATIC	468d4f2f64d16d755e2268d4817e3743b40bdbec76ed2ff447b2482c88d3ee24	policy-packages/agcf/AGCF-AWS-034/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedMcpTargetSubtypes", "type": "STRING_LIST", "defaultValue": ["MCP", "NOT_APPLICABLE"]}, {"key": "approvedMcpServerHosts", "type": "STRING_LIST", "defaultValue": ["NOT_APPLICABLE"]}]	AGCF-OBJ-AWS-034	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"not": {"in": {"parameter": "approvedMcpTargetSubtypes"}, "fact": "mcp.target_subtype_configured"}}, {"not": {"in": {"parameter": "approvedMcpServerHosts"}, "fact": "mcp.server_hostname_configured"}}]}}}	["E1", "E2"]	[]	{"fail": {"approvedMcpServerHosts": [], "approvedMcpTargetSubtypes": []}, "pass": {"approvedMcpServerHosts": ["NOT_APPLICABLE"], "approvedMcpTargetSubtypes": ["MCP", "NOT_APPLICABLE"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-035	1.0.0	SageMaker domain lacks VPC attachment	Detects when sageMaker domain lacks VPC attachment using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]	[]	[]	[{"factKey": "network.vpc_id_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "network.vpc_id_configured", "empty": true}	AGCF_AGCF_AWS_035	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "I&S-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_SAGEMAKER_DOMAIN"]	STATIC	d4b365402012676f0a0250ba30c6570a2b6ecb1dbe4b3c460e123fad162313cf	policy-packages/agcf/AGCF-AWS-035/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-035	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "network.vpc_id_configured", "empty": true}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-036	1.0.0	SageMaker endpoint, model package, or execution space is in a failed terminal state	Detects when sageMaker endpoint, model package, or execution space is in a failed terminal state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_036	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "BCR-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	fc02fa9441435d43ae05ac28673c413059567c4eb3106fec0fe0e5230b0ff9c2	policy-packages/agcf/AGCF-AWS-036/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-036	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-037	1.0.0	SageMaker notebook instance type is outside the approved compute baseline	Detects when sageMaker notebook instance type is outside the approved compute baseline using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["SAGEMAKER_DOMAINS_MODELS_ENDPOINTS"]	[]	[]	[{"factKey": "compute.instance_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedComputeTypes"}, "fact": "compute.instance_type_configured"}}	AGCF_AGCF_AWS_037	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "I&S-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "GRC-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AWS_SAGEMAKER_NOTEBOOK_INSTANCE"]	STATIC	eb83fa2afdb801fd67a1cf37c3b6214be2b19774e3abd06ca146ed3315739c21	policy-packages/agcf/AGCF-AWS-037/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedComputeTypes", "type": "STRING_LIST", "defaultValue": ["ml.t3.medium"]}]	AGCF-OBJ-AWS-037	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedComputeTypes"}, "fact": "compute.instance_type_configured"}}}}	["E1"]	[]	{"fail": {"approvedComputeTypes": []}, "pass": {"approvedComputeTypes": ["ml.t3.medium"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AWS-038	1.0.0	Bedrock flow is failed or outside the approved lifecycle state	Detects when bedrock flow is failed or outside the approved lifecycle state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BEDROCK_AGENTS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}	AGCF_AGCF_AWS_038	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	377f6069bef60525f43d1fe5bda8ff8d5cde4334fd355937a58378efaa371967	policy-packages/agcf/AGCF-AWS-038/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AWS-038	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "STOPPED"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-001	1.0.0	Azure AI, ML workspace, or Search service permits unrestricted public network access	Detects when azure AI, ML workspace, or Search service permits unrestricted public network access using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["SEARCH_CONTROL_PLANE"]	[]	[]	[{"factKey": "network.public_access_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "network.public_access_configured"}	AGCF_AGCF_AZR_001	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	046bbffeaa50c65541cdb7742dcf4ced919d025579045d2007af0d84092704e2	policy-packages/agcf/AGCF-AZR-001/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-001	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "network.public_access_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-002	1.0.0	Private endpoint is absent where the tenant baseline requires one	Detects when private endpoint is absent where the tenant baseline requires one using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "network.private_endpoint_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "network.private_endpoint_count_configured", "count_eq": 0}	AGCF_AGCF_AZR_002	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "I&S-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	6439276140620f364748a6c4dff16c7f68c4fa8934336fa3b0c0686c0f481608	policy-packages/agcf/AGCF-AZR-002/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AZR-002	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "network.private_endpoint_count_configured", "count_eq": 0}}}	["E0"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-003	1.0.0	Azure AI account permits local/key authentication	Detects when azure AI account permits local/key authentication using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "identity.local_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.local_auth_enabled_configured"}	AGCF_AGCF_AZR_003	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	df812e74b06ec3d28df42cccd2c4e6394a03e8650a76b24ce1a12cfe016eb47d	policy-packages/agcf/AGCF-AZR-003/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-003	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.local_auth_enabled_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-004	1.0.0	Azure AI account lacks customer-managed-key encryption where required	Detects when azure AI account lacks customer-managed-key encryption where required using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "data.customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "data.customer_managed_key_configured"}	AGCF_AGCF_AZR_004	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "CEK-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "CEK-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	7cdc37529db58523b5fbe9c8bf7a8b1c77884d147533ba8c384c623b51d4bcc1	policy-packages/agcf/AGCF-AZR-004/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AZR-004	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "data.customer_managed_key_configured"}}}	["E0"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-005	1.0.0	Azure AI diagnostic logging is disabled	Detects when azure AI diagnostic logging is disabled using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["DIAGNOSTIC_SETTINGS"]	[]	[]	[{"factKey": "logging.diagnostic_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "logging.diagnostic_enabled_configured"}	AGCF_AGCF_AZR_005	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "LOG-07", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "LOG-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	bedc94b31e40aa4f55664b99b7dacacd73667a482068f3e36e2daf01bfb54aaf	policy-packages/agcf/AGCF-AZR-005/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-005	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "logging.diagnostic_enabled_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-006	1.0.0	Diagnostic settings have no enabled destination	Detects when diagnostic settings have no enabled destination using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["DIAGNOSTIC_SETTINGS"]	[]	[]	[{"factKey": "logging.diagnostic_destination_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "logging.diagnostic_destination_configured"}	AGCF_AGCF_AZR_006	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "LOG-07", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	2af6dcd38095ab9090be5ff78990ccf8afba8042ea693603eaa08083f46dfd3b	policy-packages/agcf/AGCF-AZR-006/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-006	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "logging.diagnostic_destination_configured"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-007	1.0.0	Managed AI resource provisioning state is failed or non-succeeded	Detects when managed AI resource provisioning state is failed or non-succeeded using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "resource.provisioning_state_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "CANCELED", "DELETING"], "fact": "resource.provisioning_state_observed"}	AGCF_AGCF_AZR_007	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "INFORMATIVE", "frameworkVersion": "2026"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	10f2a258b173eb96c6f05e9b63fafbe4dd5dd3db8bf3a52bfdac51e8fb62e593	policy-packages/agcf/AGCF-AZR-007/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-007	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "CANCELED", "DELETING"], "fact": "resource.provisioning_state_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-008	1.0.0	Managed AI resource lacks a confirmed owner tag	Detects when managed AI resource lacks a confirmed owner tag using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "owner.owner_tag_present_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "owner.owner_tag_present_configured"}	AGCF_AGCF_AZR_008	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "DCS-07", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "GRC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	ece3b78208cfaae29c247c8ff78a1554f387b1c94d8617ad59677f64d2e5f2fb	policy-packages/agcf/AGCF-AZR-008/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-008	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "owner.owner_tag_present_configured"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-009	1.0.0	Managed AI resource lacks required environment or criticality tags	Detects when managed AI resource lacks required environment or criticality tags using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "resource.required_tags_present_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "resource.required_tags_present_configured"}	AGCF_AGCF_AZR_009	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "DCS-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DCS-07", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "GRC-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_AI_ACCOUNTS", "AZURE_ML_WORKSPACES", "AZURE_SEARCH_SERVICES"]	STATIC	98eb727f433b21c7bbb7966cd8c7a3bd384ad692845fbe6775e9b1fe264b6e7b	policy-packages/agcf/AGCF-AZR-009/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AZR-009	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "resource.required_tags_present_configured"}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-011	1.0.0	Azure RAI policy has no content-filter definitions	Detects when azure RAI policy has no content-filter definitions using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["FOUNDRY_DEPLOYMENTS_RAI"]	[]	[]	[{"factKey": "guardrail.rai_filter_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.rai_filter_count_configured", "count_eq": 0}	AGCF_AGCF_AZR_011	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM10", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	065cf0952abfc7d4a84f26f7e9a353fcf52d5451d9d09c4355c710fae4d49bc6	policy-packages/agcf/AGCF-AZR-011/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-011	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.rai_filter_count_configured", "count_eq": 0}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-013	1.0.0	RAI mode or base policy is outside the approved baseline	Detects when rAI mode or base policy is outside the approved baseline using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["FOUNDRY_DEPLOYMENTS_RAI"]	[]	[]	[{"factKey": "guardrail.rai_mode_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "guardrail.rai_base_policy_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"not": {"in": {"parameter": "approvedRaiModes"}, "fact": "guardrail.rai_mode_configured"}}, {"not": {"in": {"parameter": "approvedRaiBasePolicies"}, "fact": "guardrail.rai_base_policy_configured"}}]}	AGCF_AGCF_AZR_013	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "CCC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_RAI_POLICIES"]	STATIC	9e824a72c65ea1ba5c97d77caa043cef4da26951a62f5bc5716669f4f50ff4d5	policy-packages/agcf/AGCF-AZR-013/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedRaiModes", "type": "STRING_LIST", "defaultValue": ["Default"]}, {"key": "approvedRaiBasePolicies", "type": "STRING_LIST", "defaultValue": ["Microsoft.Default"]}]	AGCF-OBJ-AZR-013	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"not": {"in": {"parameter": "approvedRaiModes"}, "fact": "guardrail.rai_mode_configured"}}, {"not": {"in": {"parameter": "approvedRaiBasePolicies"}, "fact": "guardrail.rai_base_policy_configured"}}]}}}	["E1"]	[]	{"fail": {"approvedRaiModes": [], "approvedRaiBasePolicies": []}, "pass": {"approvedRaiModes": ["Default"], "approvedRaiBasePolicies": ["Microsoft.Default"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-014	1.0.0	Required custom blocklist baseline is absent	Detects when required custom blocklist baseline is absent using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "guardrail.rai_custom_blocklist_count_configured", "valueType": "NUMBER", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "guardrail.rai_custom_blocklist_count_configured", "count_eq": 0}	AGCF_AGCF_AZR_014	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM07", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "TVM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "GRC-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_RAI_POLICIES"]	STATIC	c17014f0ca16723456cc795d8b04c52f784298d79f1f3254837b39e1c341c16e	policy-packages/agcf/AGCF-AZR-014/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AZR-014	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "guardrail.rai_custom_blocklist_count_configured", "count_eq": 0}}}	["E1"]	[]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-015	1.0.0	Foundry model name or publisher is outside the approved allowlist	Detects when foundry model name or publisher is outside the approved allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "model.name_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "model.publisher_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"not": {"in": {"parameter": "approvedModelNames"}, "fact": "model.name_configured"}}, {"not": {"in": {"parameter": "approvedModelPublishers"}, "fact": "model.publisher_configured"}}]}	AGCF_AGCF_AZR_015	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "STA-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-12", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_FOUNDRY_DEPLOYMENTS"]	STATIC	52a3ebeb4e58935dc7b1a6b5837b1319bf26d98d4c9c1532cc2ccf84ab06450c	policy-packages/agcf/AGCF-AZR-015/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedModelNames", "type": "STRING_LIST", "defaultValue": []}, {"key": "approvedModelPublishers", "type": "STRING_LIST", "defaultValue": ["Microsoft"]}]	AGCF-OBJ-AZR-015	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"not": {"in": {"parameter": "approvedModelNames"}, "fact": "model.name_configured"}}, {"not": {"in": {"parameter": "approvedModelPublishers"}, "fact": "model.publisher_configured"}}]}}}	["E1"]	[]	{"fail": {"approvedModelNames": ["CERTIFICATION_APPROVED_VALUE"], "approvedModelPublishers": []}, "pass": {"approvedModelNames": [], "approvedModelPublishers": ["Microsoft"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-016	1.0.0	Foundry model version or upgrade option violates the patch/lifecycle baseline	Detects when foundry model version or upgrade option violates the patch/lifecycle baseline using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AI_ACCOUNTS"]	[]	[]	[{"factKey": "model.version_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "model.version_upgrade_option_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"not": {"in": {"parameter": "approvedModelVersions"}, "fact": "model.version_configured"}}, {"not": {"in": {"parameter": "approvedUpgradeOptions"}, "fact": "model.version_upgrade_option_configured"}}]}	AGCF_AGCF_AZR_016	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "TVM-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "CCC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_FOUNDRY_DEPLOYMENTS"]	STATIC	3071eec263ebb4a9d468da373cd2d7d6aa2d80925277828f7ac069de7fc72a4f	policy-packages/agcf/AGCF-AZR-016/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedModelVersions", "type": "STRING_LIST", "defaultValue": []}, {"key": "approvedUpgradeOptions", "type": "STRING_LIST", "defaultValue": ["OnceNewDefaultVersionAvailable"]}]	AGCF-OBJ-AZR-016	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"not": {"in": {"parameter": "approvedModelVersions"}, "fact": "model.version_configured"}}, {"not": {"in": {"parameter": "approvedUpgradeOptions"}, "fact": "model.version_upgrade_option_configured"}}]}}}	["E1"]	[]	{"fail": {"approvedModelVersions": ["CERTIFICATION_APPROVED_VALUE"], "approvedUpgradeOptions": []}, "pass": {"approvedModelVersions": [], "approvedUpgradeOptions": ["OnceNewDefaultVersionAvailable"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-017	1.0.0	Foundry agent has Code Interpreter enabled outside an approved scope	Detects when foundry agent has Code Interpreter enabled outside an approved scope using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["FOUNDRY_AGENTS_TOOLS"]	[]	[]	[{"factKey": "agent.code_interpreter_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "agent.code_interpreter_enabled_configured"}	AGCF_AGCF_AZR_017	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM10", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "AIS-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	2616adf6abb03e4fcf61349130285dceb34122f2198da2ca35f52ac254f39359	policy-packages/agcf/AGCF-AZR-017/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBaseline", "type": "STRING", "defaultValue": "DEFAULT"}]	AGCF-OBJ-AZR-017	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "agent.code_interpreter_enabled_configured"}}}	["E0"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	{"fail": {"approvedBaseline": "STRICT"}, "pass": {"approvedBaseline": "DEFAULT"}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-018	1.0.0	Foundry agent model deployment is absent or outside the approved allowlist	Detects when foundry agent model deployment is absent or outside the approved allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["FOUNDRY_AGENTS_TOOLS"]	[]	[]	[{"factKey": "agent.model_deployment_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "agent.model_deployment_configured", "empty": true}	AGCF_AGCF_AZR_018	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	999807ed8ca6bd7ba48349624be80bb44b4ea70e33a9c6a8f12ebff3550e7184	policy-packages/agcf/AGCF-AZR-018/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-018	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "agent.model_deployment_configured", "empty": true}}}	["E1"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-019	1.0.0	Foundry MCP server uses NONE or UNKNOWN configured authentication	Detects when foundry MCP server uses NONE or UNKNOWN configured authentication using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["FOUNDRY_AGENTS_TOOLS"]	[]	[]	[{"factKey": "mcp.configured_auth_type", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.configured_auth_type"}	AGCF_AGCF_AZR_019	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	d444cf2eabef606ab116a7bab9dd4f112b8c3e7f91d31e90151540f3badecc4b	policy-packages/agcf/AGCF-AZR-019/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-019	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["NONE", "UNKNOWN", ""], "fact": "mcp.configured_auth_type"}}}	["E0"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-020	1.0.0	Foundry MCP server hostname is outside the approved allowlist	Detects when foundry MCP server hostname is outside the approved allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["FOUNDRY_AGENTS_TOOLS"]	[]	[]	[{"factKey": "mcp.server_hostname_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedMcpServerHosts"}, "fact": "mcp.server_hostname_configured"}}	AGCF_AGCF_AZR_020	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM01", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "STA-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_FOUNDRY_MCP_SERVER"]	STATIC	055a6129236c68ef0997e2486d3b1aed1ca25be2fe376167ea34e4d9a6afb97a	policy-packages/agcf/AGCF-AZR-020/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedMcpServerHosts", "type": "STRING_LIST", "defaultValue": []}]	AGCF-OBJ-AZR-020	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedMcpServerHosts"}, "fact": "mcp.server_hostname_configured"}}}}	["E1"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	{"fail": {"approvedMcpServerHosts": ["CERTIFICATION_APPROVED_VALUE"]}, "pass": {"approvedMcpServerHosts": []}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-021	1.0.0	Foundry agent uses a tool type outside the approved tool allowlist	Detects when foundry agent uses a tool type outside the approved tool allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["FOUNDRY_AGENTS_TOOLS"]	[]	[]	[{"factKey": "agent.tool_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedToolTypes"}, "fact": "agent.tool_type_configured"}}	AGCF_AGCF_AZR_021	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_FOUNDRY_AGENT_TOOLS"]	STATIC	e4e301f70db0173986a0064c08067a528c8956e2703697e6f6101760c5492250	policy-packages/agcf/AGCF-AZR-021/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedToolTypes", "type": "STRING_LIST", "defaultValue": ["function"]}]	AGCF-OBJ-AZR-021	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedToolTypes"}, "fact": "agent.tool_type_configured"}}}}	["E1"]	["PURVIEW_CLASSIFICATION", "FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE"]	{"fail": {"approvedToolTypes": []}, "pass": {"approvedToolTypes": ["function"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-023	1.0.0	Azure ML endpoint traffic references a missing or non-ready deployment	Detects when azure ML endpoint traffic references a missing or non-ready deployment using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["ML_WORKSPACES_ENDPOINTS"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[{"factKey": "ml.endpoint_traffic_configured", "valueType": "OBJECT", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"fact": "ml.endpoint_traffic_configured", "empty": true}	AGCF_AGCF_AZR_023	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "CCC-06", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_ML_ENDPOINTS"]	STATIC	e50b5f26ed18870f2723e9ea177effab94e25cbf0dad9f501c386ae5b10a075f	policy-packages/agcf/AGCF-AZR-023/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-023	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"fact": "ml.endpoint_traffic_configured", "empty": true}}}	["E1", "E2"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-024	1.0.0	Azure ML deployment instance type or model reference is outside the approved baseline	Detects when azure ML deployment instance type or model reference is outside the approved baseline using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["ML_WORKSPACES_ENDPOINTS"]	[]	[]	[{"factKey": "compute.instance_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "ml.model_reference_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"not": {"in": {"parameter": "approvedComputeTypes"}, "fact": "compute.instance_type_configured"}}, {"not": {"in": {"parameter": "approvedModelReferences"}, "fact": "ml.model_reference_configured"}}]}	AGCF_AGCF_AZR_024	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-02", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_ML_DEPLOYMENTS"]	STATIC	74d0fd1107a27fbee282e4fe9a2e2b99977668adc79715b277ca0ca6abf1520a	policy-packages/agcf/AGCF-AZR-024/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedComputeTypes", "type": "STRING_LIST", "defaultValue": []}, {"key": "approvedModelReferences", "type": "STRING_LIST", "defaultValue": []}]	AGCF-OBJ-AZR-024	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"not": {"in": {"parameter": "approvedComputeTypes"}, "fact": "compute.instance_type_configured"}}, {"not": {"in": {"parameter": "approvedModelReferences"}, "fact": "ml.model_reference_configured"}}]}}}	["E1"]	[]	{"fail": {"approvedComputeTypes": ["CERTIFICATION_APPROVED_VALUE"], "approvedModelReferences": ["CERTIFICATION_APPROVED_VALUE"]}, "pass": {"approvedComputeTypes": [], "approvedModelReferences": []}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-025	1.0.0	Azure ML job or pipeline is in a failed terminal state	Detects when azure ML job or pipeline is in a failed terminal state using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["ML_WORKSPACES_ENDPOINTS"]	[]	[]	[{"factKey": "resource.status_observed", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"in": ["FAILED", "CANCELED"], "fact": "resource.status_observed"}	AGCF_AGCF_AZR_025	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-01", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "MDS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	ca67ac614ec02a61f27d2bb4118bd51f0132c5f662421b22825612006b7e87c8	policy-packages/agcf/AGCF-AZR-025/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-025	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"in": ["FAILED", "CANCELED"], "fact": "resource.status_observed"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-026	1.0.0	Azure AI Search permits local admin-key authentication	Detects when azure AI Search permits local admin-key authentication using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["SEARCH_CONTROL_PLANE"]	[]	[]	[{"factKey": "identity.search_local_admin_auth_enabled_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.search_local_admin_auth_enabled_configured"}	AGCF_AGCF_AZR_026	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "LLM09", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-16", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	534500676194bbde05c1c2071fb22612c101a7b7994f6f8a1c793754a854810c	policy-packages/agcf/AGCF-AZR-026/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-026	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.search_local_admin_auth_enabled_configured"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-027	1.0.0	Azure Bot uses password authentication without managed identity	Detects when azure Bot uses password authentication without managed identity using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["BOT_CONFIGURATION"]	[]	[]	[{"factKey": "identity.bot_password_without_managed_identity_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.bot_password_without_managed_identity_observed"}	AGCF_AGCF_AZR_027	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-13", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	31946f2b9733f78d7a02865edf162a74ef6c295e9adf19832466e9981c3bb833	policy-packages/agcf/AGCF-AZR-027/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-027	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.bot_password_without_managed_identity_observed"}}}	["E0"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-028	1.0.0	Azure Bot has no managed identity where the baseline requires one	Detects when azure Bot has no managed identity where the baseline requires one using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	ENABLED	[]	["BOT_CONFIGURATION"]	[]	[]	[{"factKey": "identity.managed_identity_assigned_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": false, "fact": "identity.managed_identity_assigned_configured"}	AGCF_AGCF_AZR_028	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	a1b5d9432ee0554b15446b519ceefc2100e4010fb0b2cb82f615fef949061233	policy-packages/agcf/AGCF-AZR-028/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-AZR-028	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": false, "fact": "identity.managed_identity_assigned_configured"}}}	["E1"]	[]	null	AGCF_PHASE_1	PHASE_1
AGCF-AZR-029	1.0.0	Azure Bot channel is outside the approved channel allowlist	Detects when azure Bot channel is outside the approved channel allowlist using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["BOT_CONFIGURATION"]	[]	[]	[{"factKey": "bot.channel_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedBotChannels"}, "fact": "bot.channel_type_configured"}}	AGCF_AGCF_AZR_029	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "STA-08", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "AIS-11", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_BOT_CHANNELS"]	STATIC	e484838e945bd0df97f75305668091f5397e4f39f6a991505513a6ba43f92884	policy-packages/agcf/AGCF-AZR-029/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedBotChannels", "type": "STRING_LIST", "defaultValue": ["DirectLineChannel"]}]	AGCF-OBJ-AZR-029	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedBotChannels"}, "fact": "bot.channel_type_configured"}}}}	["E1"]	[]	{"fail": {"approvedBotChannels": []}, "pass": {"approvedBotChannels": ["DirectLineChannel"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-030	1.0.0	High-privilege Azure role assignment is broader than the approved AI resource scope	Detects when high-privilege Azure role assignment is broader than the approved AI resource scope using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	REQUIRED	[]	["RBAC_ASSIGNMENTS"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[{"factKey": "identity.assignment_scope_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"not": {"in": {"parameter": "approvedAiResourceScopes"}, "fact": "identity.assignment_scope_configured"}}	AGCF_AGCF_AZR_030	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-09", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_RBAC_GLOBAL"]	STATIC	114068db61bb49bcbee8f502f4608b8b384b6dd7336cdbf679cd6464eb24fb95	policy-packages/agcf/AGCF-AZR-030/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedAiResourceScopes", "type": "STRING_LIST", "defaultValue": []}]	AGCF-OBJ-AZR-030	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"not": {"in": {"parameter": "approvedAiResourceScopes"}, "fact": "identity.assignment_scope_configured"}}}}	["E1", "E2"]	[]	{"fail": {"approvedAiResourceScopes": ["CERTIFICATION_APPROVED_VALUE"]}, "pass": {"approvedAiResourceScopes": []}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-AZR-031	1.0.0	High-privilege Azure role assignment lacks the required condition or approved principal type	Detects when high-privilege Azure role assignment lacks the required condition or approved principal type using only declared evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["RBAC_ASSIGNMENTS"]	[]	[]	[{"factKey": "identity.assignment_condition_version_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}, {"factKey": "identity.principal_type_configured", "valueType": "STRING", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"any": [{"fact": "identity.assignment_condition_version_configured", "empty": true}, {"not": {"in": {"parameter": "approvedPrincipalTypes"}, "fact": "identity.principal_type_configured"}}]}	AGCF_AGCF_AZR_031	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "IAM-10", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-15", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	["AZURE_RBAC_GLOBAL"]	STATIC	9bcaf2cc4a18af2a5f7d9234c5ba8606a12b27eda294d10220cdd3dc8db272a1	policy-packages/agcf/AGCF-AZR-031/1.0.0.json	AI Grid Security	\N	\N	\N	[{"key": "approvedPrincipalTypes", "type": "STRING_LIST", "defaultValue": ["ServicePrincipal", "ManagedIdentity"]}]	AGCF-OBJ-AZR-031	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"any": [{"fact": "identity.assignment_condition_version_configured", "empty": true}, {"not": {"in": {"parameter": "approvedPrincipalTypes"}, "fact": "identity.principal_type_configured"}}]}}}	["E1"]	[]	{"fail": {"approvedPrincipalTypes": []}, "pass": {"approvedPrincipalTypes": ["ServicePrincipal", "ManagedIdentity"]}, "invalid": {}, "immutable": true}	AGCF_PHASE_1	PHASE_1
AGCF-XSP-001	1.0.0	Publicly reachable AI service has a direct path to confirmed sensitive data	Detects when publicly reachable AI service has a direct path to confirmed sensitive data using only declared evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	["SYSTEM"]	["MULTI_CLOUD_GRAPH"]	[]	[]	[]	{}	AGCF_AGCF_XSP_001	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "This control is independently mapped to the policy's stated security intent.", "mappingType": "DIRECT", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.868808+05:30	[]	STATIC	e94674a32c10d0c6002826434944f523f1e1180139134b4be21e5a34f1ccfa9a	policy-packages/agcf/AGCF-XSP-001/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-XSP-001	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"correlationId": "R2_EXTERNAL_SENSITIVE_ACCESS", "correlationVersion": "1.0.0"}}	["E2"]	["MACIE_CLASSIFICATION", "PURVIEW_CLASSIFICATION"]	null	AGCF_PHASE_1	PHASE_1
AGCF-AWS-039	1.0.0	Effective agent permissions exceed the approved action/resource matrix	Evaluates whether effective agent permissions exceed the approved action/resource matrix using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.effective_access_exceeds_approved_matrix", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.effective_access_exceeds_approved_matrix"}	AGCF_P2_AWS_039	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	f65fb7507d1e5625e4a32f4014d03f520cba80c5eb48f67478469a1ad0781623	policy-packages/agcf/AGCF-AWS-039/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-039	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.effective_access_exceeds_approved_matrix"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-040	1.0.0	Effective agent permissions allow cross-account sensitive-resource access	Evaluates whether effective agent permissions allow cross-account sensitive-resource access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.cross_account_sensitive_access_observed", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.cross_account_sensitive_access_observed"}	AGCF_P2_AWS_040	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	dc51be86de53ca4594aa1d24b2154dc9754bdd9c9fdd624c0b2ecda6494e8bae	policy-packages/agcf/AGCF-AWS-040/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-040	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.cross_account_sensitive_access_observed"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-041	1.0.0	Agent can pass or assume an unapproved privileged role	Evaluates whether agent can pass or assume an unapproved privileged role using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.unapproved_privileged_role_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.unapproved_privileged_role_access"}	AGCF_P2_AWS_041	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	2f70c284e52f484754686fea1ccf9db91ca3c448a641410eee9896e199ccbdd3	policy-packages/agcf/AGCF-AWS-041/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-041	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.unapproved_privileged_role_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-042	1.0.0	Boundaries or organization controls fail to restrict consequential actions	Evaluates whether boundaries or organization controls fail to restrict consequential actions using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.restriction_controls_incomplete", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.restriction_controls_incomplete"}	AGCF_P2_AWS_042	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AWS IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	0dc897d54f3830b093789a4233df1d78c21d3897a1b6235f8b42243353e2ae5b	policy-packages/agcf/AGCF-AWS-042/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-042	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.restriction_controls_incomplete"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-043	1.0.0	AI-linked S3 effective Block Public Access is incomplete	Evaluates whether ai-linked s3 effective block public access is incomplete using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_effective_block_public_access_incomplete", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_effective_block_public_access_incomplete"}	AGCF_P2_AWS_043	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	a4c50aa5003455b38f9f2c48952062c3c9d89a76a6255b460ebdf8451490655d	policy-packages/agcf/AGCF-AWS-043/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-043	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_effective_block_public_access_incomplete"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-044	1.0.0	AI-linked S3 default encryption is absent	Evaluates whether ai-linked s3 default encryption is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_default_encryption_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_default_encryption_configured"}	AGCF_P2_AWS_044	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	05a02f13eee7643f7bc75b58fe1a9079797a8507eb4f79d241a7aabf28d68e51	policy-packages/agcf/AGCF-AWS-044/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-044	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_default_encryption_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-045	1.0.0	AI-linked S3 lacks a required customer-managed key	Evaluates whether ai-linked s3 lacks a required customer-managed key using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_customer_managed_key_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_customer_managed_key_configured"}	AGCF_P2_AWS_045	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	568301c4417b9b7726722add6a9b4b1cca2ad9bb3755c2b8186e6a11cf0ca3b5	policy-packages/agcf/AGCF-AWS-045/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-045	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_customer_managed_key_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-046	1.0.0	AI-linked S3 permits unapproved cross-account principals	Evaluates whether ai-linked s3 permits unapproved cross-account principals using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_unapproved_cross_account_principal", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_unapproved_cross_account_principal"}	AGCF_P2_AWS_046	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	4a2e475e377d89afe650a69065cd045019ba0bafa4164f598726bc3770eb5bc9	policy-packages/agcf/AGCF-AWS-046/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-046	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_unapproved_cross_account_principal"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-047	1.0.0	AI-linked S3 does not enforce TLS	Evaluates whether ai-linked s3 does not enforce tls using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_tls_enforced", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_tls_enforced"}	AGCF_P2_AWS_047	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	99cfd58324c35c39ee91af86462ed4ba8b6005561e4579cbd27cefe3edaf1a9d	policy-packages/agcf/AGCF-AWS-047/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-047	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_tls_enforced"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-048	1.0.0	Referenced vector store permits public network access	Evaluates whether referenced vector store permits public network access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.vector_store_public_network_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.vector_store_public_network_access"}	AGCF_P2_AWS_048	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	ba738411028ebcceedb01f44d74ae96a0010d3ef1a9e85c2479b8c4a4a125d32	policy-packages/agcf/AGCF-AWS-048/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-048	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.vector_store_public_network_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-049	1.0.0	Referenced vector store lacks required encryption	Evaluates whether referenced vector store lacks required encryption using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.vector_store_encryption_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.vector_store_encryption_configured"}	AGCF_P2_AWS_049	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	d346a10537f2e6cf0e6e0a78bf69bd64529e1c21cf8c4fd4e978b093721abebb	policy-packages/agcf/AGCF-AWS-049/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-049	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.vector_store_encryption_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-050	1.0.0	Vector-store access policy lacks an approved tenant/principal boundary	Evaluates whether vector-store access policy lacks an approved tenant/principal boundary using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.vector_store_principal_boundary_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.vector_store_principal_boundary_configured"}	AGCF_P2_AWS_050	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	4ef980e6a022d78ff83a2ef042f92e51b9a9013f3e44b66789fef6fd8ac6ff58	policy-packages/agcf/AGCF-AWS-050/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-050	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.vector_store_principal_boundary_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-051	1.0.0	Bedrock consumption budget is absent	Evaluates whether bedrock consumption budget is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.bedrock_budget_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.bedrock_budget_configured"}	AGCF_P2_AWS_051	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AWS COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	6c6418efcd439c170bcf5cf68d1691c71f40a5d55a1daaeaab79dcaeabda1d4f	policy-packages/agcf/AGCF-AWS-051/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-051	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.bedrock_budget_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-052	1.0.0	Bedrock quota-utilization alarm is absent	Evaluates whether bedrock quota-utilization alarm is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.bedrock_quota_alarm_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.bedrock_quota_alarm_configured"}	AGCF_P2_AWS_052	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AWS COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	6a8eb00ba0c2971b2edfd6943e11ca50f72cc5d981b325a06b0094b44f7f1fe0	policy-packages/agcf/AGCF-AWS-052/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-052	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.bedrock_quota_alarm_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-053	1.0.0	Bedrock quota utilization exceeds the configured threshold	Evaluates whether bedrock quota utilization exceeds the configured threshold using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.bedrock_quota_utilization_exceeds_threshold", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.bedrock_quota_utilization_exceeds_threshold"}	AGCF_P2_AWS_053	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AWS COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	816a3b1ffd6622d4fa2896f33695ff58b6474dd900c4f4abbfbad2b0e498632b	policy-packages/agcf/AGCF-AWS-053/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-053	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.bedrock_quota_utilization_exceeds_threshold"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-054	1.0.0	Bedrock throttling exceeds threshold without an effective alarm	Evaluates whether bedrock throttling exceeds threshold without an effective alarm using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.bedrock_throttling_alarm_effective", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.bedrock_throttling_alarm_effective"}	AGCF_P2_AWS_054	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AWS COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	4b1a97e38b1d182bdeb22fda62d4273071940660b5ae4f68a13c14c7db578340	policy-packages/agcf/AGCF-AWS-054/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-054	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.bedrock_throttling_alarm_effective"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-055	1.0.0	Bedrock token or invocation consumption exceeds threshold	Evaluates whether bedrock token or invocation consumption exceeds threshold using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.bedrock_usage_exceeds_threshold", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.bedrock_usage_exceeds_threshold"}	AGCF_P2_AWS_055	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AWS COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	7e671e094188d22f289ee1a6708daf9e49fc0475d310d9a8275aa405de9070f7	policy-packages/agcf/AGCF-AWS-055/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-055	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.bedrock_usage_exceeds_threshold"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-056	1.0.0	Deployed model artifact lacks signature or attestation	Evaluates whether deployed model artifact lacks signature or attestation using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_signature_attestation_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_signature_attestation_present"}	AGCF_P2_AWS_056	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	725539d6b65c7952d4aee935e4f8973f73da00920c2704d54ae3e6ec83b594e1	policy-packages/agcf/AGCF-AWS-056/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-056	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_signature_attestation_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-057	1.0.0	Deployed model lacks approved registry lineage	Evaluates whether deployed model lacks approved registry lineage using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_approved_registry_lineage", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_approved_registry_lineage"}	AGCF_P2_AWS_057	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	4ebf2481c85b86751e5559850be809c1bbb6a6cabfe4f55f3013ee22575b75f7	policy-packages/agcf/AGCF-AWS-057/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-057	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_approved_registry_lineage"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-058	1.0.0	Deployed model lacks AI-BOM/SBOM coverage	Evaluates whether deployed model lacks ai-bom/sbom coverage using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_sbom_coverage_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_sbom_coverage_present"}	AGCF_P2_AWS_058	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	e82012c3453635e1024af03d6b16f52629b71ed65c22aaa965fa473d38243d28	policy-packages/agcf/AGCF-AWS-058/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-058	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_sbom_coverage_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-059	1.0.0	Referenced model-serving artifact has high/critical vulnerabilities	Evaluates whether referenced model-serving artifact has high/critical vulnerabilities using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_vulnerability_baseline_pass", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_vulnerability_baseline_pass"}	AGCF_P2_AWS_059	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	1245dc9f019ba7cab57df7a0e1dcaf9262437915dc7b81c9bf8d474d5f835986	policy-packages/agcf/AGCF-AWS-059/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-059	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_vulnerability_baseline_pass"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-060	1.0.0	Training or retrieval dataset version/checksum is not pinned	Evaluates whether training or retrieval dataset version/checksum is not pinned using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.dataset_version_checksum_pinned", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.dataset_version_checksum_pinned"}	AGCF_P2_AWS_060	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS DATA evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	e2d673b71ed7fd5785c588c1a90fb3a26c8d6db42a5274e4b87dd4fb0454577d	policy-packages/agcf/AGCF-AWS-060/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-060	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.dataset_version_checksum_pinned"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-061	1.0.0	Dataset provenance or ingestion lineage is missing	Evaluates whether dataset provenance or ingestion lineage is missing using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.dataset_lineage_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.dataset_lineage_present"}	AGCF_P2_AWS_061	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS DATA evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	ea22a87f5e05e89b16b3b044f6c1f0c1118dc472d6cc4b0d7247c1dce44cd92c	policy-packages/agcf/AGCF-AWS-061/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-061	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.dataset_lineage_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-062	1.0.0	Referenced dataset changed after approved ingestion	Evaluates whether referenced dataset changed after approved ingestion using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.dataset_changed_after_approval", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.dataset_changed_after_approval"}	AGCF_P2_AWS_062	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS DATA evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "AWS DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	b50d61c519e83a4dc6b97480d28ede27ab41562ac98f7acbc17f7feaf7208265	policy-packages/agcf/AGCF-AWS-062/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-062	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.dataset_changed_after_approval"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-063	1.0.0	AgentCore/MCP endpoint is public without adequate authentication	Evaluates whether agentcore/mcp endpoint is public without adequate authentication using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "mcp.endpoint_public_without_adequate_auth", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.endpoint_public_without_adequate_auth"}	AGCF_P2_AWS_063	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	ca0390e0157638dc7eba759b7c7d5e4841a5a85fcc4356e511af8540e9c7ab80	policy-packages/agcf/AGCF-AWS-063/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-063	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.endpoint_public_without_adequate_auth"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-064	1.0.0	MCP endpoint does not meet the configured TLS baseline	Evaluates whether mcp endpoint does not meet the configured tls baseline using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "mcp.endpoint_tls_baseline_pass", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.endpoint_tls_baseline_pass"}	AGCF_P2_AWS_064	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	0604be8c6c7822a05f6527acd80443dd2c8a423b5171172a16a60a4bc7b591e5	policy-packages/agcf/AGCF-AWS-064/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-064	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.endpoint_tls_baseline_pass"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-065	1.0.0	SageMaker network isolation is disabled	Evaluates whether sagemaker network isolation is disabled using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.sagemaker_network_isolation_enabled", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.sagemaker_network_isolation_enabled"}	AGCF_P2_AWS_065	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	00868538a96e53778413aa54530378d8aa363a1ea14adf0bc7d8c960ac9a343e	policy-packages/agcf/AGCF-AWS-065/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-065	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.sagemaker_network_isolation_enabled"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-066	1.0.0	SageMaker storage lacks a required customer-managed key	Evaluates whether sagemaker storage lacks a required customer-managed key using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.sagemaker_storage_customer_managed_key", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.sagemaker_storage_customer_managed_key"}	AGCF_P2_AWS_066	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	7cde89aba8accd3367cd452614defc11c66f83679c6285a877f82a5499c9afd7	policy-packages/agcf/AGCF-AWS-066/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-066	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.sagemaker_storage_customer_managed_key"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-067	1.0.0	SageMaker root access is enabled	Evaluates whether sagemaker root access is enabled using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.sagemaker_root_access_enabled", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.sagemaker_root_access_enabled"}	AGCF_P2_AWS_067	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	8f78ac884e75213443cf552ff01f538c90ed3e69feac1778f50781f05ba8e1c6	policy-packages/agcf/AGCF-AWS-067/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-067	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.sagemaker_root_access_enabled"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-068	1.0.0	SageMaker image integrity or vulnerability baseline fails	Evaluates whether sagemaker image integrity or vulnerability baseline fails using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.sagemaker_image_baseline_pass", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.sagemaker_image_baseline_pass"}	AGCF_P2_AWS_068	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AWS MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	38fe98563122b0f80f02a78fb6945e6ebc127e137b96ae7a201c5be8efd7ec0b	policy-packages/agcf/AGCF-AWS-068/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-068	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.sagemaker_image_baseline_pass"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-054	1.0.0	Quota-utilization alert is absent	Evaluates whether quota-utilization alert is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.azure_quota_alert_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.azure_quota_alert_configured"}	AGCF_P2_AZURE_054	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AZURE COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	9ff00b52ec011a1d5ea3575274a3fc978c8321a7f347e8fbfdae631dc04c1f4a	policy-packages/agcf/AGCF-AZR-054/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-054	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.azure_quota_alert_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-033	1.0.0	Effective AI principal permissions exceed the approved matrix	Evaluates whether effective ai principal permissions exceed the approved matrix using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.effective_access_exceeds_approved_matrix", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.effective_access_exceeds_approved_matrix"}	AGCF_P2_AZURE_033	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	5e82e65006e3da5e89d9d8434d8b60d755346c2d8bad321e4c84dd1360761574	policy-packages/agcf/AGCF-AZR-033/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-033	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.effective_access_exceeds_approved_matrix"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-034	1.0.0	Effective AI principal reaches sensitive resources outside approved scope	Evaluates whether effective ai principal reaches sensitive resources outside approved scope using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.sensitive_access_outside_approved_scope", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.sensitive_access_outside_approved_scope"}	AGCF_P2_AZURE_034	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	b83b09e4a30b83798f1437128487e27d41207fcd678d9f7e686e372655693a91	policy-packages/agcf/AGCF-AZR-034/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-034	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.sensitive_access_outside_approved_scope"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-035	1.0.0	AI principal can create role assignments or elevate access	Evaluates whether ai principal can create role assignments or elevate access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.can_elevate_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.can_elevate_access"}	AGCF_P2_AZURE_035	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	dbaef20696b1421c7317995dfc6f4da96247edf8f4bbb1554f6921aa92ef49dd	policy-packages/agcf/AGCF-AZR-035/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-035	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.can_elevate_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-036	1.0.0	Custom AI role contains high-impact wildcard permissions	Evaluates whether custom ai role contains high-impact wildcard permissions using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.high_impact_wildcard_permission", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.high_impact_wildcard_permission"}	AGCF_P2_AZURE_036	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	65195885a5619fe3a73b2e3ab3347ed95753683d7bdef486b438fd339cb0efe5	policy-packages/agcf/AGCF-AZR-036/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-036	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.high_impact_wildcard_permission"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-037	1.0.0	AI-linked role assignment is stale beyond the baseline	Evaluates whether ai-linked role assignment is stale beyond the baseline using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.role_assignment_stale", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.role_assignment_stale"}	AGCF_P2_AZURE_037	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	4e751fda2d083554bc1023bac70e8323813872b8edfc158dab7354a86a9b2cd1	policy-packages/agcf/AGCF-AZR-037/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-037	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.role_assignment_stale"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-038	1.0.0	Required PIM activation is absent	Evaluates whether required pim activation is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.pim_activation_required_missing", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.pim_activation_required_missing"}	AGCF_P2_AZURE_038	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	bff48e1563aaa8090c6d9a915c40e72dd1307c8ed56535c72c3529ac6d3bf290	policy-packages/agcf/AGCF-AZR-038/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-038	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.pim_activation_required_missing"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-039	1.0.0	Required access review is absent or stale	Evaluates whether required access review is absent or stale using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.access_review_missing_or_stale", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.access_review_missing_or_stale"}	AGCF_P2_AZURE_039	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	b13e699106326a27eccbd9cd7e2d63b292ac1218d0c5cff0d72a8f985e9f1f4c	policy-packages/agcf/AGCF-AZR-039/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-039	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.access_review_missing_or_stale"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-040	1.0.0	Search data source uses key, SAS, or secret authentication	Evaluates whether search data source uses key, sas, or secret authentication using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.data_source_secret_authentication", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.data_source_secret_authentication"}	AGCF_P2_AZURE_040	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c6723ee8888588f091002423ed3cfa0de7e7e6a5ea5811c69075299b37373624	policy-packages/agcf/AGCF-AZR-040/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-040	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.data_source_secret_authentication"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-041	1.0.0	Search connection lacks required CMK protection	Evaluates whether search connection lacks required cmk protection using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.connection_customer_managed_key", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.connection_customer_managed_key"}	AGCF_P2_AZURE_041	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	3793eae46d61e0829fbbca9ca844a3b14f6fbcf91ae5b74aa02978b9dcc979de	policy-packages/agcf/AGCF-AZR-041/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-041	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.connection_customer_managed_key"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-042	1.0.0	Search index lacks required permission filtering	Evaluates whether search index lacks required permission filtering using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.permission_filtering_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.permission_filtering_configured"}	AGCF_P2_AZURE_042	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	ba202b1b71c4d8765f48a840d670ee1e06977926a5f7a2131d967256d5c9d70c	policy-packages/agcf/AGCF-AZR-042/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-042	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.permission_filtering_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-043	1.0.0	Search index lacks document-level authorization	Evaluates whether search index lacks document-level authorization using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.document_authorization_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.document_authorization_configured"}	AGCF_P2_AZURE_043	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	bf535779c6ad183ba407495f8f5698b60db12fafc5db2cc99cd7de24cab4b68a	policy-packages/agcf/AGCF-AZR-043/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-043	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.document_authorization_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-044	1.0.0	Search index lacks tenant partitioning	Evaluates whether search index lacks tenant partitioning using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.tenant_partitioning_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.tenant_partitioning_configured"}	AGCF_P2_AZURE_044	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c2c4e0d6e10540e01845d1a670099c0234a31e8b7dc089e12abee4d3a7a8c565	policy-packages/agcf/AGCF-AZR-044/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-044	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.tenant_partitioning_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-045	1.0.0	Search retrieval mode is outside the approved baseline	Evaluates whether search retrieval mode is outside the approved baseline using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.retrieval_mode_approved", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.retrieval_mode_approved"}	AGCF_P2_AZURE_045	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	84f7987ca19ad9cf69bf7ef3a7eb59265f1d8ee3f12f287fc401ef0c8248e898	policy-packages/agcf/AGCF-AZR-045/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-045	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.retrieval_mode_approved"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-046	1.0.0	Search service or object lacks required CMK encryption	Evaluates whether search service or object lacks required cmk encryption using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.encryption_customer_managed_key", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.encryption_customer_managed_key"}	AGCF_P2_AZURE_046	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	fe6b8e09e3f66b43a8aadb0eaec06129c94dffbf275c230e129d3ed5a56b88f2	policy-packages/agcf/AGCF-AZR-046/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-046	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.encryption_customer_managed_key"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-047	1.0.0	Search outbound shared-private-link control is absent	Evaluates whether search outbound shared-private-link control is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "search.outbound_shared_private_link_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "search.outbound_shared_private_link_configured"}	AGCF_P2_AZURE_047	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	335a98f32fe7a5a7e12b9a5c3bab773890bbc1b85b75b4bc51bc88fb2c059a21	policy-packages/agcf/AGCF-AZR-047/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-047	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "search.outbound_shared_private_link_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-048	1.0.0	AI-linked Storage permits public blob access	Evaluates whether ai-linked storage permits public blob access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.storage_public_blob_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.storage_public_blob_access"}	AGCF_P2_AZURE_048	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	b01c06b890df243e2b8645dd0534a871a1cd0b7c6457c8f6cb4428c3d6bc6c1d	policy-packages/agcf/AGCF-AZR-048/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-048	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.storage_public_blob_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-049	1.0.0	AI-linked Storage permits shared-key access	Evaluates whether ai-linked storage permits shared-key access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.storage_shared_key_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.storage_shared_key_access"}	AGCF_P2_AZURE_049	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	9616857c48f05dc504b81711b31e55ebcff91fc4c39ae9ac69f49b41450ed909	policy-packages/agcf/AGCF-AZR-049/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-049	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.storage_shared_key_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-050	1.0.0	AI-linked Storage fails secure-transfer or minimum-TLS requirements	Evaluates whether ai-linked storage fails secure-transfer or minimum-tls requirements using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.storage_secure_transfer_tls_baseline", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.storage_secure_transfer_tls_baseline"}	AGCF_P2_AZURE_050	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	faa4944111b07d7bf826b730aa8b9778ee765e64948ecf173adb3321d53dc352	policy-packages/agcf/AGCF-AZR-050/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-050	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.storage_secure_transfer_tls_baseline"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-051	1.0.0	AI-linked Storage lacks required CMK encryption	Evaluates whether ai-linked storage lacks required cmk encryption using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.storage_customer_managed_key", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.storage_customer_managed_key"}	AGCF_P2_AZURE_051	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	02273a88d7435c80f5c6b9afa47798dec110352c5fd624f6a103578eeeda3fc6	policy-packages/agcf/AGCF-AZR-051/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-051	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.storage_customer_managed_key"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-052	1.0.0	AI-linked Storage uses default-allow networking without a private endpoint	Evaluates whether ai-linked storage uses default-allow networking without a private endpoint using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.storage_private_network_boundary", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.storage_private_network_boundary"}	AGCF_P2_AZURE_052	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	e97e5df9fe344b33075c07d3ea9f578b4313bf6b50efa8bd3fa77902543b3901	policy-packages/agcf/AGCF-AZR-052/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-052	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.storage_private_network_boundary"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-055	1.0.0	Quota utilization exceeds threshold	Evaluates whether quota utilization exceeds threshold using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.azure_quota_utilization_exceeds_threshold", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.azure_quota_utilization_exceeds_threshold"}	AGCF_P2_AZURE_055	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AZURE COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	87e7d4025ef67aec744a3a3ab56db267a01142f8e0a1b9022267ea675f1e3167	policy-packages/agcf/AGCF-AZR-055/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-055	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.azure_quota_utilization_exceeds_threshold"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-056	1.0.0	Throttling or capacity saturation exceeds threshold	Evaluates whether throttling or capacity saturation exceeds threshold using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.azure_throttling_capacity_exceeds_threshold", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.azure_throttling_capacity_exceeds_threshold"}	AGCF_P2_AZURE_056	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AZURE COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c65d68a6c45b28ff8c17d943824bfb226e0521362ece941a7b877a4ed9951357	policy-packages/agcf/AGCF-AZR-056/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-056	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.azure_throttling_capacity_exceeds_threshold"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-057	1.0.0	Token or request consumption exceeds threshold	Evaluates whether token or request consumption exceeds threshold using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_CONSUMPTION_TELEMETRY"]	[]	[]	[{"factKey": "consumption.azure_usage_exceeds_threshold", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "consumption.azure_usage_exceeds_threshold"}	AGCF_P2_AZURE_057	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM06", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE COST evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LOG-14", "framework": "CSA_AICM", "rationale": "AZURE COST normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	438e0b4d0376f3173e23efd7f2c87b213d3135397b86b8ca1349620b515e95ef	policy-packages/agcf/AGCF-AZR-057/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-057	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "consumption.azure_usage_exceeds_threshold"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-058	1.0.0	Deployed model lacks signature or attestation	Evaluates whether deployed model lacks signature or attestation using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_signature_attestation_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_signature_attestation_present"}	AGCF_P2_AZURE_058	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	751f3c437672b737fe172e13153c2b93430103b705d41899452b625b41c6a3ad	policy-packages/agcf/AGCF-AZR-058/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-058	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_signature_attestation_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-059	1.0.0	Deployed model lacks approved registry lineage	Evaluates whether deployed model lacks approved registry lineage using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_approved_registry_lineage", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_approved_registry_lineage"}	AGCF_P2_AZURE_059	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	0e2a862d3ac3e53cfb9df8a8f3b4346d8c13d1d22bb4836caf84ead67e4735d2	policy-packages/agcf/AGCF-AZR-059/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-059	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_approved_registry_lineage"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-060	1.0.0	Deployed model lacks AI-BOM/SBOM coverage	Evaluates whether deployed model lacks ai-bom/sbom coverage using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.model_sbom_coverage_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.model_sbom_coverage_present"}	AGCF_P2_AZURE_060	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	1720a4c88e6095ddc109e67f074a0726a1722e3e11294402b87b94646a674524	policy-packages/agcf/AGCF-AZR-060/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-060	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.model_sbom_coverage_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-061	1.0.0	Referenced deployment image has high/critical vulnerabilities	Evaluates whether referenced deployment image has high/critical vulnerabilities using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.deployment_image_vulnerability_baseline_pass", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.deployment_image_vulnerability_baseline_pass"}	AGCF_P2_AZURE_061	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	3fbe44e7f135abc0cddf72358ea9588b6481931d1b9f18114727211b058451a0	policy-packages/agcf/AGCF-AZR-061/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-061	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.deployment_image_vulnerability_baseline_pass"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-062	1.0.0	Training or retrieval dataset version/checksum is not pinned	Evaluates whether training or retrieval dataset version/checksum is not pinned using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.dataset_version_checksum_pinned", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.dataset_version_checksum_pinned"}	AGCF_P2_AZURE_062	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE DATA evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "AZURE DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	ee8b9effd3f9dbca12106a0e96c853b9707d0c2b8b88e431e4d0da4f4ccae159	policy-packages/agcf/AGCF-AZR-062/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-062	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.dataset_version_checksum_pinned"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-063	1.0.0	MLflow or dataset lineage is missing	Evaluates whether mlflow or dataset lineage is missing using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "provenance.mlflow_dataset_lineage_present", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "provenance.mlflow_dataset_lineage_present"}	AGCF_P2_AZURE_063	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM05", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE DATA evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-09", "framework": "CSA_AICM", "rationale": "AZURE DATA normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	206baff9f75fa53e5cf9effc18a96fd5f60ff2322ac1911fb53aecf4159a904f	policy-packages/agcf/AGCF-AZR-063/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-063	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "provenance.mlflow_dataset_lineage_present"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-064	1.0.0	Azure ML workspace managed network is absent	Evaluates whether azure ml workspace managed network is absent using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.azure_ml_managed_network_enabled", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.azure_ml_managed_network_enabled"}	AGCF_P2_AZURE_064	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	3e31720f666b0c5d3853700db8ddfb339f7e4bc2cb6330f14c2c377ce35a16e1	policy-packages/agcf/AGCF-AZR-064/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-064	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.azure_ml_managed_network_enabled"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-065	1.0.0	Azure ML deployment has unrestricted outbound egress	Evaluates whether azure ml deployment has unrestricted outbound egress using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_MODEL_DATA_PROVENANCE"]	[]	[]	[{"factKey": "model.azure_ml_outbound_egress_restricted", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "model.azure_ml_outbound_egress_restricted"}	AGCF_P2_AZURE_065	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM04", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MODEL evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "MDS-02", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "MDS-08", "framework": "CSA_AICM", "rationale": "AZURE MODEL normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	58a09b7cb68fb30b08ae12af745a5a69a20446df7587fde75b704c4b0483cdda	policy-packages/agcf/AGCF-AZR-065/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-065	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "model.azure_ml_outbound_egress_restricted"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-066	1.0.0	Bot endpoint is publicly exposed without strong authentication	Evaluates whether bot endpoint is publicly exposed without strong authentication using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "mcp.bot_public_without_strong_auth", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.bot_public_without_strong_auth"}	AGCF_P2_AZURE_066	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c2cbf73d5bb0ffa5aad29f15ac50b3d8421397b4db8a03639e32f96c86165860	policy-packages/agcf/AGCF-AZR-066/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-066	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.bot_public_without_strong_auth"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-067	1.0.0	Bot uses secret-based credentials where managed identity is required	Evaluates whether bot uses secret-based credentials where managed identity is required using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "mcp.bot_managed_identity_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.bot_managed_identity_configured"}	AGCF_P2_AZURE_067	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	bdcc7f582f83ee92d4d84fb97d63970e01ab8bada67035519aa1304eda7cebb3	policy-packages/agcf/AGCF-AZR-067/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-067	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.bot_managed_identity_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-068	1.0.0	Bot endpoint fails the configured TLS baseline	Evaluates whether bot endpoint fails the configured tls baseline using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "mcp.bot_tls_baseline_pass", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.bot_tls_baseline_pass"}	AGCF_P2_AZURE_068	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	f73b582a881bf256f67e31f504ea706fac65942f89fa91ce7f637dd3033363b3	policy-packages/agcf/AGCF-AZR-068/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-068	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.bot_tls_baseline_pass"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-069	1.0.0	Foundry MCP lacks the required private endpoint	Evaluates whether foundry mcp lacks the required private endpoint using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "mcp.foundry_private_endpoint_configured", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.foundry_private_endpoint_configured"}	AGCF_P2_AZURE_069	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE MCP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE MCP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	771ef58fc5c984f1d67964649d97600fd772f19dad0a2298f01f0733ca5cd3d3	policy-packages/agcf/AGCF-AZR-069/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-069	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.foundry_private_endpoint_configured"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-069	1.0.0	Authoritative effective public-access evidence for the linked S3 resource	Evaluates whether authoritative effective public-access evidence for the linked s3 resource using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_effective_public_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_effective_public_access"}	AGCF_P2_AWS_069	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	fc7c1e8d34741a61e9a276409fe868e632c653c64ba8a2511257cf0ad5ec7761	policy-packages/agcf/AGCF-AWS-069/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-069	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_effective_public_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-070	1.0.0	Confirmed sensitivity plus authoritative effective public-content access	Evaluates whether confirmed sensitivity plus authoritative effective public-content access using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.s3_effective_public_content_access", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.s3_effective_public_content_access"}	AGCF_P2_AWS_070	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	d64d01a0d1b951006359f5321fb7fa85ded55a242e0c0076a2224c82075f9963	policy-packages/agcf/AGCF-AWS-070/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-070	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.s3_effective_public_content_access"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-071	1.0.0	Authoritative AgentCore gateway inbound-auth classification and completeness	Evaluates whether authoritative agentcore gateway inbound-auth classification and completeness using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "mcp.inbound_auth_authoritative", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.inbound_auth_authoritative"}	AGCF_P2_AWS_071	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	56c5d728cf1d7eade6a455cce0484baebbfbc3e355ddc0adfa515b75e3857f25	policy-packages/agcf/AGCF-AWS-071/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-071	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.inbound_auth_authoritative"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AWS-072	1.0.0	Authoritative AgentCore target outbound-auth classification and completeness	Evaluates whether authoritative agentcore target outbound-auth classification and completeness using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AWS_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "mcp.outbound_auth_authoritative", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.outbound_auth_authoritative"}	AGCF_P2_AWS_072	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AWS STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AWS STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AWS_AI_LINKED_RESOURCE"]	STATIC	4be06c4433280d058f82ef2e437179d3c96404aa828cb76b0351da4ab1f32238	policy-packages/agcf/AGCF-AWS-072/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AWS-072	AWS	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.outbound_auth_authoritative"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-070	1.0.0	Authoritative effective public-network exposure for the linked AI resource	Evaluates whether authoritative effective public-network exposure for the linked ai resource using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "network.effective_public_network_exposure", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "network.effective_public_network_exposure"}	AGCF_P2_AZURE_070	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	0aa2935fe1f01465f87fcd3e74f5878faa0746da947b2930a51c5edc7f8dda45	policy-packages/agcf/AGCF-AZR-070/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-070	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "network.effective_public_network_exposure"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-071	1.0.0	Authoritative private-path requirement and effective private-endpoint evidence	Evaluates whether authoritative private-path requirement and effective private-endpoint evidence using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "network.effective_private_endpoint_requirement", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "network.effective_private_endpoint_requirement"}	AGCF_P2_AZURE_071	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	5875020211d7f6a177a017a7a61dba4369e099a50698db5bb02a631531a7a9a4	policy-packages/agcf/AGCF-AZR-071/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-071	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "network.effective_private_endpoint_requirement"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-072	1.0.0	Secret-safe authoritative Foundry MCP authentication classification	Evaluates whether secret-safe authoritative foundry mcp authentication classification using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_SEARCH_MCP_SECURITY"]	[]	[]	[{"factKey": "mcp.foundry_auth_authoritative", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "mcp.foundry_auth_authoritative"}	AGCF_P2_AZURE_072	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	848568738e9733674a5b6cb76a9438a35742919b644799c1c65567473836a499	policy-packages/agcf/AGCF-AZR-072/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-072	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "mcp.foundry_auth_authoritative"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-073	1.0.0	Effective privileged RBAC reach outside the approved AI scope	Evaluates whether effective privileged rbac reach outside the approved ai scope using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.effective_privileged_scope", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.effective_privileged_scope"}	AGCF_P2_AZURE_073	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	7cc28e0d9f5e84b4d368e6097eb45ae09206a979938a51a7c1ae7aaff6b658ef	policy-packages/agcf/AGCF-AZR-073/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-073	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.effective_privileged_scope"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-074	1.0.0	Effective role constraints, deny assignments, condition, and approved-principal evidence	Evaluates whether effective role constraints, deny assignments, condition, and approved-principal evidence using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_EFFECTIVE_ACCESS"]	[]	[]	[{"factKey": "identity.effective_role_constraints", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "identity.effective_role_constraints"}	AGCF_P2_AZURE_074	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE IAM evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-05", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "AZURE IAM normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c0e4f1952361bd54103cb1a76265c74afb7115bd2e5e7675a2dce114aef1191f	policy-packages/agcf/AGCF-AZR-074/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-074	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "identity.effective_role_constraints"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-AZR-075	1.0.0	Authoritative sensitivity state with explicit unknown/failed/stale handling	Evaluates whether authoritative sensitivity state with explicit unknown/failed/stale handling using bounded, normalized provider evidence.	HIGH	VALIDATED	POSTURE_FINDING	DISABLED	[]	["AZURE_LINKED_DATA_STORES"]	[]	[]	[{"factKey": "data.authoritative_sensitivity_state", "valueType": "BOOLEAN", "maxAgeSeconds": 86400, "evidenceClasses": ["CONFIGURATION"]}]	{"eq": true, "fact": "data.authoritative_sensitivity_state"}	AGCF_P2_AZURE_075	Correct the provider configuration or relationship and reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "AZURE STORE evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "I&S-03", "framework": "CSA_AICM", "rationale": "AZURE STORE normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["AZURE_AI_LINKED_RESOURCE"]	STATIC	c82fa5e59641fdcdd4266de421986006f2bd956e656aaf766b8626e09df9528d	policy-packages/agcf/AGCF-AZR-075/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-AZURE-075	AZURE	ARTIFACT_FACTS	{"mode": "ARTIFACT_FACTS", "artifactFacts": {"predicate": {"eq": true, "fact": "data.authoritative_sensitivity_state"}}}	["E1"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-007	1.0.0	Effective public entry point reaches an authoritatively confirmed sensitive store	Evaluates effective public entry point reaches an authoritatively confirmed sensitive store only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_007	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	38295898e29907ea76b52a7479ec72a4afdf5540c774064cc4472bda9785349a	policy-packages/agcf/XSP-007/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-007	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.effective_public_sensitive_path", "correlationId": "XSP-007", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-008	1.0.0	Effective consequential tool permission reaches an authoritative sensitive-data path	Evaluates effective consequential tool permission reaches an authoritative sensitive-data path only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_008	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	fedfbfb21240fd6dd5e9da910cfac2fae4599aeb383a55618ec87e76c56c955b	policy-packages/agcf/XSP-008/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-008	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.effective_tool_sensitive_path", "correlationId": "XSP-008", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-009	1.0.0	Effective IAM/RBAC decision reaches a high-impact agent tool	Evaluates effective iam/rbac decision reaches a high-impact agent tool only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_009	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	2cee0cc2e9ebef9f2b57106b67ff555e68b41ac3b5b09a0f5f06e4667e5f181e	policy-packages/agcf/XSP-009/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-009	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.effective_identity_tool_path", "correlationId": "XSP-009", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-010	1.0.0	Authoritatively unapproved/external MCP path reaches sensitive data through the agent	Evaluates authoritatively unapproved/external mcp path reaches sensitive data through the agent only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_010	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	50abb49aeb5585c9a0b06f94bf61ff4c6445681490ea3dbc07f8e4bc5fc7d89a	policy-packages/agcf/XSP-010/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-010	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.unapproved_mcp_sensitive_path", "correlationId": "XSP-010", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-011	1.0.0	Secret-safe MCP auth classification plus effective high-impact tool permissions validates the path	Evaluates secret-safe mcp auth classification plus effective high-impact tool permissions validates the path only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_011	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	762dce72867d65581ee9a27b48940d002d71571a473db671bae76feb73d09064	policy-packages/agcf/XSP-011/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-011	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.mcp_auth_tool_path", "correlationId": "XSP-011", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
AGCF-XSP-012	1.0.0	Search ACL, tenant isolation, retrieval mode, and sensitive-data evidence validate the retrieval path	Evaluates search acl, tenant isolation, retrieval mode, and sensitive-data evidence validate the retrieval path only from complete, fresh relationship evidence.	HIGH	VALIDATED	VALIDATED_EXPOSURE	REQUIRED	[]	["MULTI_CLOUD_GRAPH"]	["DIRECT_PROVIDER_RELATIONSHIP"]	[]	[]	{}	AGCF_P2_XSP_012	Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.	[{"controlId": "LLM02", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "LLM03", "framework": "OWASP_GENAI_LLM_TOP_10", "rationale": "MULTI_CLOUD XSP evidence contributes directly to this risk but is not a certification claim.", "mappingType": "PARTIAL", "frameworkVersion": "2026"}, {"controlId": "IAM-18", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}, {"controlId": "DSP-17", "framework": "CSA_AICM", "rationale": "MULTI_CLOUD XSP normalized evidence contributes to this control.", "mappingType": "PARTIAL", "frameworkVersion": "1.1"}]	\N	\N	\N	2026-09-03 07:14:18.968589+05:30	["MULTI_CLOUD_GRAPH"]	STATIC	91886fbbcabb756256ba2cc63451b299b15ab5dad6208d2a077892a73159af80	policy-packages/agcf/XSP-012/1.0.0.json	AI Grid Security	\N	\N	\N	[]	AGCF-OBJ-P2-XSP-012	MULTI_CLOUD	CORRELATION_PATH	{"mode": "CORRELATION_PATH", "correlationPath": {"maxDepth": 4, "maxFanOut": 50, "decisiveFact": "exposure.search_sensitive_retrieval_path", "correlationId": "XSP-012", "correlationVersion": "1.0.0"}}	["E2"]	[]	null	AGCF_PHASE_2	PHASE_2
\.


--
-- Data for Name: ai_grid_relationship_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_relationship_definitions (relationship_type, source, directional, lifecycle, description) FROM stdin;
USES_MODEL	OBSERVATION_V1	t	ACTIVE	Artifact uses a model.
USES_GUARDRAIL	OBSERVATION_V1	t	ACTIVE	Artifact uses a guardrail.
USES_KNOWLEDGE_BASE	OBSERVATION_V1	t	ACTIVE	Artifact uses a knowledge base.
USES_DATA_SOURCE	OBSERVATION_V1	t	ACTIVE	Artifact uses a data source.
BACKED_BY_DATA_STORE	OBSERVATION_V1	t	ACTIVE	Artifact is backed by a data store.
USES_SEARCH_INDEX	OBSERVATION_V1	t	ACTIVE	Artifact uses a search index.
EXPOSES_MCP	OBSERVATION_V1	t	ACTIVE	Artifact exposes MCP.
CONNECTS_TO_MCP	OBSERVATION_V1	t	ACTIVE	Artifact connects to MCP.
CONTAINS_MCP_TARGET	OBSERVATION_V1	t	ACTIVE	Gateway contains an MCP target.
ROUTES_TO	OBSERVATION_V1	t	ACTIVE	Artifact routes to another artifact.
INVOKES_LAMBDA	OBSERVATION_V1	t	ACTIVE	Artifact invokes Lambda.
ASSUMES_ROLE	OBSERVATION_V1	t	ACTIVE	Artifact assumes a role.
READS_FROM_S3	OBSERVATION_V1	t	ACTIVE	Artifact reads from S3.
LOGS_TO	OBSERVATION_V1	t	ACTIVE	Artifact logs to a destination.
SUPERVISES_AGENT	OBSERVATION_V1	t	ACTIVE	Artifact supervises an agent.
CONTAINS_PROJECT	OBSERVATION_V1	t	ACTIVE	Artifact contains a project.
DEPLOYS_MODEL	OBSERVATION_V1	t	ACTIVE	Artifact deploys a model.
USES_TOOL	OBSERVATION_V1	t	ACTIVE	Artifact uses a tool.
USES_MANAGED_IDENTITY	OBSERVATION_V1	t	ACTIVE	Artifact uses managed identity.
HAS_PRIVATE_ENDPOINT	OBSERVATION_V1	t	ACTIVE	Artifact has a private endpoint.
USES_KEY_VAULT_KEY	OBSERVATION_V1	t	ACTIVE	Artifact uses a Key Vault key.
CONTAINS_RESOURCE	OBSERVATION_V1	t	ACTIVE	Artifact contains a resource.
HAS_DEPLOYMENT	OBSERVATION_V1	t	ACTIVE	Artifact has a deployment.
RUNS_PIPELINE	OBSERVATION_V1	t	ACTIVE	Artifact runs a pipeline.
HAS_CHANNEL	OBSERVATION_V1	t	ACTIVE	Artifact has a channel.
HAS_ROLE_ASSIGNMENT	OBSERVATION_V1	t	ACTIVE	Artifact has a role assignment.
CONTAINS	OBSERVATION_V1	t	ACTIVE	Artifact contains another artifact.
USES_EXECUTION_ROLE	OBSERVATION_V1	t	ACTIVE	Artifact uses an execution role.
USES_NETWORK	OBSERVATION_V1	t	ACTIVE	Artifact uses a network.
USES_ENDPOINT_CONFIGURATION	OBSERVATION_V1	t	ACTIVE	Artifact uses endpoint configuration.
PRODUCES_MODEL	OBSERVATION_V1	t	ACTIVE	Artifact produces a model.
USES_DATA_CONNECTION	OBSERVATION_V1	t	ACTIVE	Artifact uses a data connection.
READS_FROM_STORAGE_ACCOUNT	OBSERVATION_V1	t	ACTIVE	Artifact reads from a storage account.
DIRECT_PROVIDER_RELATIONSHIP	AI_GRID_GRAPH	t	ACTIVE	Governed one-hop graph evaluation profile.
\.


--
-- Data for Name: ai_grid_resource_family_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_resource_family_definitions (resource_family, provider, scope_semantics, lifecycle, description) FROM stdin;
BEDROCK_AGENTS	AWS	REGIONAL	ACTIVE	Bedrock Agents discovery.
BEDROCK_KNOWLEDGE_BASES	AWS	REGIONAL	ACTIVE	Bedrock knowledge base discovery.
BEDROCK_DATA_SOURCES	AWS	REGIONAL	ACTIVE	Bedrock data-source discovery.
BEDROCK_DATA_STORES	AWS	REGIONAL	ACTIVE	Bedrock data-store discovery.
AWS_AGENTCORE_GATEWAYS	AWS	REGIONAL	ACTIVE	AgentCore gateway discovery.
AWS_AGENTCORE_GATEWAY_TARGETS	AWS	REGIONAL	ACTIVE	AgentCore target discovery.
BEDROCK_GUARDRAILS	AWS	REGIONAL	ACTIVE	Bedrock Guardrails discovery.
BEDROCK_INVOCATION_LOGGING	AWS	REGIONAL	ACTIVE	Bedrock invocation logging discovery.
BEDROCK_DEPLOYABLE_MODELS	AWS	REGIONAL	ACTIVE	Bedrock model discovery.
BEDROCK_INFERENCE_PROFILES	AWS	REGIONAL	ACTIVE	Bedrock inference-profile discovery.
BEDROCK_MODEL_CUSTOMIZATION_JOBS	AWS	REGIONAL	ACTIVE	Bedrock customization-job discovery.
BEDROCK_PROMPTS	AWS	REGIONAL	ACTIVE	Bedrock prompt metadata discovery.
BEDROCK_FLOWS	AWS	REGIONAL	ACTIVE	Bedrock flow discovery.
SAGEMAKER_DOMAINS	AWS	REGIONAL	ACTIVE	SageMaker domain discovery.
SAGEMAKER_SPACES	AWS	REGIONAL	ACTIVE	SageMaker space discovery.
SAGEMAKER_MODEL_REGISTRY	AWS	REGIONAL	ACTIVE	SageMaker registry discovery.
SAGEMAKER_ENDPOINTS	AWS	REGIONAL	ACTIVE	SageMaker endpoint discovery.
SAGEMAKER_ENDPOINT_CONFIGURATIONS	AWS	REGIONAL	ACTIVE	SageMaker endpoint-configuration discovery.
SAGEMAKER_JOBS	AWS	REGIONAL	ACTIVE	SageMaker job discovery.
SAGEMAKER_PIPELINES	AWS	REGIONAL	ACTIVE	SageMaker pipeline discovery.
SAGEMAKER_COMPUTE	AWS	REGIONAL	ACTIVE	SageMaker compute discovery.
SAGEMAKER_EXECUTION_ROLES	AWS	ACCOUNT_GLOBAL	ACTIVE	SageMaker execution-role discovery.
SAGEMAKER_NETWORKING	AWS	REGIONAL	ACTIVE	SageMaker networking discovery.
LAMBDA_URLS	AWS	REGIONAL	ACTIVE	Lambda URL discovery.
S3_EXPOSURE	AWS	REGIONAL	ACTIVE	S3 exposure discovery.
AWS_MACIE_PII	AWS	REGIONAL	ACTIVE	Amazon Macie PII classification discovery.
IAM_GLOBAL	AWS	ACCOUNT_GLOBAL	ACTIVE	IAM discovery.
AZURE_AI_ACCOUNTS	AZURE	REGIONAL	ACTIVE	Azure AI account discovery.
AZURE_FOUNDRY_PROJECTS	AZURE	REGIONAL	ACTIVE	Azure Foundry project discovery.
AZURE_FOUNDRY_DEPLOYMENTS	AZURE	REGIONAL	ACTIVE	Azure Foundry deployment discovery.
AZURE_RAI_POLICIES	AZURE	REGIONAL	ACTIVE	Azure RAI policy discovery.
AZURE_FOUNDRY_AGENTS	AZURE	REGIONAL	ACTIVE	Azure Foundry agent discovery.
AZURE_FOUNDRY_AGENT_TOOLS	AZURE	REGIONAL	ACTIVE	Azure Foundry tool discovery.
AZURE_ML_WORKSPACES	AZURE	REGIONAL	ACTIVE	Azure ML workspace discovery.
AZURE_ML_MODELS	AZURE	REGIONAL	ACTIVE	Azure ML model discovery.
AZURE_ML_ENDPOINTS	AZURE	REGIONAL	ACTIVE	Azure ML endpoint discovery.
AZURE_ML_DEPLOYMENTS	AZURE	REGIONAL	ACTIVE	Azure ML deployment discovery.
AZURE_ML_COMPUTE	AZURE	REGIONAL	ACTIVE	Azure ML compute discovery.
AZURE_ML_JOBS	AZURE	REGIONAL	ACTIVE	Azure ML job discovery.
AZURE_ML_PIPELINES	AZURE	REGIONAL	ACTIVE	Azure ML pipeline discovery.
AZURE_SEARCH_SERVICES	AZURE	REGIONAL	ACTIVE	Azure AI Search service discovery.
AZURE_SEARCH_INDEXES	AZURE	REGIONAL	ACTIVE	Azure AI Search index discovery.
AZURE_SEARCH_SKILLSETS	AZURE	REGIONAL	ACTIVE	Azure AI Search skillset discovery.
AZURE_SEARCH_INDEXERS	AZURE	REGIONAL	ACTIVE	Azure AI Search indexer discovery.
AZURE_SEARCH_DATA_SOURCES	AZURE	REGIONAL	ACTIVE	Azure AI Search data-source discovery.
AZURE_SEARCH_KNOWLEDGE_BASES	AZURE	REGIONAL	ACTIVE	Azure AI Search knowledge-base discovery.
AZURE_SEARCH_KNOWLEDGE_SOURCES	AZURE	REGIONAL	ACTIVE	Azure AI Search knowledge-source discovery.
AZURE_BOT_SERVICES	AZURE	ACCOUNT_GLOBAL	ACTIVE	Azure Bot service discovery.
AZURE_BOT_CHANNELS	AZURE	ACCOUNT_GLOBAL	ACTIVE	Azure Bot channel discovery.
AZURE_BOT_IDENTITIES	AZURE	ACCOUNT_GLOBAL	ACTIVE	Azure Bot identity discovery.
AZURE_DIAGNOSTIC_SETTINGS	AZURE	REGIONAL	ACTIVE	Azure diagnostic-settings discovery.
AZURE_RBAC_GLOBAL	AZURE	ACCOUNT_GLOBAL	ACTIVE	Azure RBAC discovery.
AZURE_RBAC_ASSIGNMENTS	AZURE	REGIONAL	ACTIVE	Azure RBAC assignment discovery.
AZURE_PURVIEW_CLASSIFICATION	AZURE	REGIONAL	ACTIVE	Azure Purview classification discovery.
\.


--
-- Data for Name: ai_grid_technology_versions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.ai_grid_technology_versions (technology_id, version, display_name, provider, lifecycle, aliases_json, resource_families_json, created_at) FROM stdin;
AWS_BEDROCK	1.0.0	Amazon Bedrock	AWS	ACTIVE	[]	["BEDROCK_AGENTS", "BEDROCK_GUARDRAILS", "BEDROCK_KNOWLEDGE_BASES", "BEDROCK_INVOCATION_LOGGING"]	2026-09-03 07:14:18.788519+05:30
AZURE_AI_SERVICES	1.0.0	Azure AI Services	AZURE	ACTIVE	[]	["AZURE_AI_ACCOUNTS", "AZURE_DIAGNOSTIC_SETTINGS"]	2026-09-03 07:14:18.794726+05:30
AZURE_AI_FOUNDRY	1.0.0	Azure AI Foundry	AZURE	ACTIVE	[]	["AZURE_FOUNDRY_PROJECTS", "AZURE_FOUNDRY_DEPLOYMENTS", "AZURE_FOUNDRY_AGENTS", "AZURE_FOUNDRY_AGENT_TOOLS"]	2026-09-03 07:14:18.794726+05:30
AZURE_MACHINE_LEARNING	1.0.0	Azure Machine Learning	AZURE	ACTIVE	[]	["AZURE_ML_WORKSPACES", "AZURE_ML_MODELS", "AZURE_ML_ENDPOINTS", "AZURE_ML_DEPLOYMENTS", "AZURE_ML_COMPUTE", "AZURE_ML_JOBS", "AZURE_ML_PIPELINES"]	2026-09-03 07:14:18.794726+05:30
AZURE_AI_SEARCH	1.0.0	Azure AI Search	AZURE	ACTIVE	[]	["AZURE_SEARCH_SERVICES", "AZURE_SEARCH_INDEXES", "AZURE_SEARCH_SKILLSETS", "AZURE_SEARCH_INDEXERS", "AZURE_SEARCH_DATA_SOURCES"]	2026-09-03 07:14:18.794726+05:30
AZURE_BOT_SERVICE	1.0.0	Azure Bot Service	AZURE	ACTIVE	[]	["AZURE_BOT_SERVICES", "AZURE_BOT_CHANNELS", "AZURE_BOT_IDENTITIES"]	2026-09-03 07:14:18.794726+05:30
UNMAPPED_AI_TECHNOLOGY	1.0.0	Unmapped AI technology	UNKNOWN	ACTIVE	[]	[]	2026-09-03 07:14:18.794726+05:30
AZURE_AI_SERVICES	1.1.0	Azure AI Services	AZURE	ACTIVE	[]	["AZURE_AI_ACCOUNTS", "AZURE_DIAGNOSTIC_SETTINGS", "AZURE_RAI_POLICIES"]	2026-09-03 07:14:18.82034+05:30
\.


--
-- Data for Name: entitlement_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at) FROM stdin;
ai.investigation_summary	AI	BOOLEAN	Generate AI investigation summaries	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.solution_generation	AI	BOOLEAN	Generate AI remediation solutions	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.required_actions	AI	BOOLEAN	Generate AI required actions	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.fix_generation	AI	BOOLEAN	Generate AI fix records	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.upgrade_recommendation	AI	BOOLEAN	Generate AI upgrade recommendations	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.investigation_agent	AI	BOOLEAN	Run AI investigation agent workflows	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ai.security	AI_SECURITY	BOOLEAN	Access the AI Security module (inventory, findings, policies)	2026-09-03 07:14:18.782052+05:30	2026-09-03 07:14:18.782052+05:30
\.


--
-- Data for Name: plan_definitions; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.plan_definitions (code, display_name, status, description, created_at, updated_at) FROM stdin;
PRO	Pro	ACTIVE	Legacy commercial plan label retained for compatibility	2026-09-03 07:14:18.711089+05:30	2026-09-03 07:14:18.711089+05:30
ENTERPRISE	Enterprise	ACTIVE	Default workspace plan label retained for compatibility	2026-09-03 07:14:18.711089+05:30	2026-09-03 07:14:18.711089+05:30
DEMO	Demo	ACTIVE	Demo tenant plan label retained for compatibility	2026-09-03 07:14:18.711089+05:30	2026-09-03 07:14:18.711089+05:30
PILOT	Pilot	ACTIVE	Legacy pilot plan retained for compatibility	2026-09-03 07:14:18.711089+05:30	2026-09-03 07:14:18.711089+05:30
\.


--
-- Data for Name: plan_entitlements; Type: TABLE DATA; Schema: platform; Owner: -
--

COPY platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at) FROM stdin;
PRO	ai.investigation_summary	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.investigation_summary	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.investigation_summary	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.investigation_summary	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.solution_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.solution_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.solution_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.solution_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.required_actions	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.required_actions	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.required_actions	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.required_actions	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.fix_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.fix_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.fix_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.fix_generation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.upgrade_recommendation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.upgrade_recommendation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.upgrade_recommendation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.upgrade_recommendation	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.investigation_agent	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
ENTERPRISE	ai.investigation_agent	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
DEMO	ai.investigation_agent	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PILOT	ai.investigation_agent	t	\N	2026-09-03 07:14:18.734178+05:30	2026-09-03 07:14:18.734178+05:30
PRO	ai.security	f	\N	2026-09-03 07:14:18.782052+05:30	2026-09-03 07:14:18.782052+05:30
ENTERPRISE	ai.security	f	\N	2026-09-03 07:14:18.782052+05:30	2026-09-03 07:14:18.782052+05:30
DEMO	ai.security	f	\N	2026-09-03 07:14:18.782052+05:30	2026-09-03 07:14:18.782052+05:30
PILOT	ai.security	f	\N	2026-09-03 07:14:18.782052+05:30	2026-09-03 07:14:18.782052+05:30
\.


--
-- PostgreSQL database dump complete
--
