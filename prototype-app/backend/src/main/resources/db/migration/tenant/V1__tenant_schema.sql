-- Consolidated clean-slate tenant baseline. Generated from the ordered V42–V68 tenant catalog.

-- source: V42__enforce_tenant_rls.sql
-- Executed once per tenant schema by TenantSchemaMigrationService.
-- ${tenantId} and ${tenantSchema} are validated values supplied by the control plane.
DO $tenant_rls$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    table_record record;
    has_tenant_id boolean;
    tenant_id_nullable boolean;
    conflict_count bigint;
    has_tenant_fk boolean;
    tenant_fk_name text;
    predicate text;
BEGIN
    IF current_schema() <> target_schema THEN
        RAISE EXCEPTION 'Tenant migration search_path mismatch: expected %, got %', target_schema, current_schema();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM platform.tenants
        WHERE id = target_tenant AND schema_name = target_schema
    ) THEN
        RAISE EXCEPTION 'Tenant/schema registration mismatch for %', target_schema;
    END IF;

    FOR table_record IN
        SELECT c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = target_schema
          AND c.relkind IN ('r', 'p')
          AND c.relname NOT IN ('tenant_schema_history', 'flyway_schema_history')
        ORDER BY c.relname
    LOOP
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = target_schema
              AND table_name = table_record.table_name
              AND column_name = 'tenant_id'
        ) INTO has_tenant_id;

        IF NOT has_tenant_id THEN
            EXECUTE format('ALTER TABLE %I.%I ADD COLUMN tenant_id uuid', target_schema, table_record.table_name);
            EXECUTE format('UPDATE %I.%I SET tenant_id = $1 WHERE tenant_id IS NULL', target_schema, table_record.table_name)
                USING target_tenant;
            EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                           target_schema, table_record.table_name, target_tenant::text);
            EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN tenant_id SET NOT NULL', target_schema, table_record.table_name);
            has_tenant_id := true;
        END IF;

        EXECUTE format('SELECT count(*) FROM %I.%I WHERE tenant_id IS NOT NULL AND tenant_id <> $1',
                       target_schema, table_record.table_name)
            INTO conflict_count USING target_tenant;
        IF conflict_count > 0 THEN
            RAISE EXCEPTION 'Conflicting tenant_id values in %.% (% rows)',
                target_schema, table_record.table_name, conflict_count;
        END IF;

        SELECT EXISTS (
            SELECT 1
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_namespace n ON n.oid = rel.relnamespace
            JOIN pg_class referenced ON referenced.oid = con.confrelid
            JOIN pg_namespace referenced_ns ON referenced_ns.oid = referenced.relnamespace
            WHERE n.nspname = target_schema
              AND rel.relname = table_record.table_name
              AND con.contype = 'f'
              AND referenced_ns.nspname = 'platform'
              AND referenced.relname = 'tenants'
              AND pg_get_constraintdef(con.oid) LIKE 'FOREIGN KEY (tenant_id)%'
        ) INTO has_tenant_fk;
        IF NOT has_tenant_fk THEN
            tenant_fk_name := left(table_record.table_name || '_tenant_id_fkey', 63);
            EXECUTE format(
                'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) NOT VALID',
                target_schema, table_record.table_name, tenant_fk_name
            );
            EXECUTE format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I',
                           target_schema, table_record.table_name, tenant_fk_name);
        END IF;

        SELECT is_nullable = 'YES'
          INTO tenant_id_nullable
          FROM information_schema.columns
         WHERE table_schema = target_schema
           AND table_name = table_record.table_name
           AND column_name = 'tenant_id';

        predicate := format(
            'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid',
            target_tenant::text
        );
        IF NOT tenant_id_nullable THEN
            predicate := predicate ||
                ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid';
        END IF;

        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', target_schema, table_record.table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I.%I USING (%s) WITH CHECK (%s)',
                       target_schema, table_record.table_name, predicate, predicate);
    END LOOP;
END
$tenant_rls$;


-- source: V43__repair_tenant_id_nullability.sql
-- Repair tenant_id columns that existed before V42 and therefore retained
-- their legacy nullable definition and weaker policy predicate.
DO $tenant_rls_repair$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    table_record record;
    conflict_count bigint;
    predicate text;
BEGIN
    IF current_schema() <> target_schema THEN
        RAISE EXCEPTION 'Tenant migration search_path mismatch: expected %, got %', target_schema, current_schema();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM platform.tenants
        WHERE id = target_tenant AND schema_name = target_schema
    ) THEN
        RAISE EXCEPTION 'Tenant/schema registration mismatch for %', target_schema;
    END IF;

    FOR table_record IN
        SELECT c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = target_schema
          AND c.relkind IN ('r', 'p')
          AND c.relname NOT IN ('tenant_schema_history', 'flyway_schema_history')
        ORDER BY c.relname
    LOOP
        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE tenant_id IS NOT NULL AND tenant_id <> $1',
            target_schema, table_record.table_name
        ) INTO conflict_count USING target_tenant;
        IF conflict_count > 0 THEN
            RAISE EXCEPTION 'Conflicting tenant_id values in %.% (% rows)',
                target_schema, table_record.table_name, conflict_count;
        END IF;

        EXECUTE format(
            'UPDATE %I.%I SET tenant_id = $1 WHERE tenant_id IS NULL',
            target_schema, table_record.table_name
        ) USING target_tenant;
        EXECUTE format(
            'ALTER TABLE %I.%I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
            target_schema, table_record.table_name, target_tenant::text
        );
        EXECUTE format(
            'ALTER TABLE %I.%I ALTER COLUMN tenant_id SET NOT NULL',
            target_schema, table_record.table_name
        );

        predicate := format(
            'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid'
            ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid',
            target_tenant::text
        );
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target_schema, table_record.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', target_schema, table_record.table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I.%I USING (%s) WITH CHECK (%s)',
            target_schema, table_record.table_name, predicate, predicate
        );
    END LOOP;
END
$tenant_rls_repair$;


-- source: V44__tenant_finding_workspace_projection.sql
-- Repair legacy reset migrations V3/V4, which created these derived tables in
-- public. Projection data is rebuildable, so every tenant receives a clean,
-- schema-local and RLS-protected copy.

-- demo_requests is a pre-tenant control-plane workflow. Its existing tenant_id
-- records the tenant provisioned after approval, so it cannot also serve as an
-- isolation discriminator before that tenant exists. Keep this explicit
-- exemption until the table is moved to the platform schema.
ALTER TABLE demo_requests ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE demo_requests ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE demo_requests DISABLE ROW LEVEL SECURITY;
ALTER TABLE demo_requests NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON demo_requests;

-- Audit events also include pre-authentication/platform events for which no
-- tenant exists. Keep tenant events isolated while allowing only null-context
-- callers to write and read null-tenant audit rows.
ALTER TABLE audit_events ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE audit_events ALTER COLUMN tenant_id DROP DEFAULT;
DROP POLICY IF EXISTS tenant_isolation ON audit_events;
CREATE POLICY tenant_isolation ON audit_events
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id', true), '') IS NULL)
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id', true), '') IS NULL)
    );

-- Findings may be linked directly to an asset or indirectly through a
-- component. Preserve the supported direct-asset path.
ALTER TABLE findings ALTER COLUMN component_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN asset_id DROP NOT NULL;

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
    first_observed_at timestamptz,
    tenant_id uuid
);

CREATE TABLE IF NOT EXISTS finding_workspace_projection_status (
    projection_key varchar(64) PRIMARY KEY,
    last_computed_at timestamptz NOT NULL,
    finding_count bigint NOT NULL,
    source_finding_count bigint NOT NULL DEFAULT 0,
    last_rebuild_duration_ms bigint,
    tenant_id uuid
);

ALTER TABLE finding_list_projection ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE finding_workspace_projection_status ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS source_finding_count bigint NOT NULL DEFAULT 0;
ALTER TABLE finding_workspace_projection_status
    ADD COLUMN IF NOT EXISTS last_rebuild_duration_ms bigint;

UPDATE finding_list_projection SET tenant_id = '${tenantId}'::uuid WHERE tenant_id IS NULL;
UPDATE finding_workspace_projection_status SET tenant_id = '${tenantId}'::uuid WHERE tenant_id IS NULL;

ALTER TABLE finding_list_projection ALTER COLUMN tenant_id SET DEFAULT '${tenantId}'::uuid;
ALTER TABLE finding_list_projection ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE finding_workspace_projection_status ALTER COLUMN tenant_id SET DEFAULT '${tenantId}'::uuid;
ALTER TABLE finding_workspace_projection_status ALTER COLUMN tenant_id SET NOT NULL;

DO $constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'finding_list_projection'::regclass
          AND conname = 'finding_list_projection_tenant_id_fkey'
    ) THEN
        ALTER TABLE finding_list_projection
            ADD CONSTRAINT finding_list_projection_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'finding_workspace_projection_status'::regclass
          AND conname = 'finding_workspace_projection_status_tenant_id_fkey'
    ) THEN
        ALTER TABLE finding_workspace_projection_status
            ADD CONSTRAINT finding_workspace_projection_status_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id);
    END IF;
END
$constraints$;

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

ALTER TABLE finding_list_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_list_projection FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON finding_list_projection;
CREATE POLICY tenant_isolation ON finding_list_projection
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE finding_workspace_projection_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_workspace_projection_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON finding_workspace_projection_status;
CREATE POLICY tenant_isolation ON finding_workspace_projection_status
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);


-- source: V45__ai_security_bounded_context.sql
CREATE TABLE IF NOT EXISTS ai_security_connector_configs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    role_arn varchar(512),
    external_id_ciphertext text,
    regions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, account_id)
);

CREATE TABLE IF NOT EXISTS ai_security_artifacts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    provider_resource_id varchar(1024) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    name varchar(512) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    deactivated_at timestamptz,
    UNIQUE (tenant_id, provider, provider_resource_id)
);

CREATE TABLE IF NOT EXISTS ai_security_artifact_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL,
    scope_key varchar(512) NOT NULL,
    run_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    evidence_hash varchar(128) NOT NULL,
    UNIQUE (tenant_id, artifact_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_security_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    source_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    target_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    relationship_type varchar(128) NOT NULL,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    scope_key varchar(512) NOT NULL,
    run_id uuid NOT NULL,
    active boolean NOT NULL DEFAULT true,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, source_artifact_id, target_artifact_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS ai_security_snapshot_scopes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    scope_key varchar(512) NOT NULL,
    status varchar(32) NOT NULL,
    expected_chunks integer NOT NULL DEFAULT 1,
    accepted_chunks integer NOT NULL DEFAULT 0,
    diagnostic_code varchar(64),
    diagnostic_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, run_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_security_observation_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    scope_key varchar(512) NOT NULL,
    chunk_sequence integer NOT NULL,
    idempotency_key varchar(256) NOT NULL,
    content_hash varchar(128) NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, scope_key, chunk_sequence),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS ai_security_policy_settings (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    enabled boolean NOT NULL,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_security_policy_evaluations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    outcome varchar(32) NOT NULL,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_findings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    display_id varchar(64) NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    severity varchar(32) NOT NULL,
    status varchar(32) NOT NULL,
    title varchar(512) NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    resolved_at timestamptz,
    UNIQUE (tenant_id, display_id),
    UNIQUE (tenant_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_finding_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES ai_security_findings(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL,
    reason text,
    policy_version varchar(32) NOT NULL,
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_security_artifacts_type_active
    ON ai_security_artifacts (artifact_type, active, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_artifacts_scope
    ON ai_security_artifacts (account_id, region, native_kind);
CREATE INDEX IF NOT EXISTS idx_ai_security_relationships_source
    ON ai_security_relationships (source_artifact_id, active);
CREATE INDEX IF NOT EXISTS idx_ai_security_relationships_target
    ON ai_security_relationships (target_artifact_id, active);
CREATE INDEX IF NOT EXISTS idx_ai_security_scopes_run_status
    ON ai_security_snapshot_scopes (run_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_security_evaluations_policy_outcome
    ON ai_security_policy_evaluations (policy_id, outcome, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_findings_status_severity
    ON ai_security_findings (status, severity, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_security_reviews_finding
    ON ai_security_finding_reviews (finding_id, reviewed_at DESC);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_security_connector_configs',
        'ai_security_artifacts',
        'ai_security_artifact_sources',
        'ai_security_relationships',
        'ai_security_snapshot_scopes',
        'ai_security_observation_receipts',
        'ai_security_policy_settings',
        'ai_security_policy_evaluations',
        'ai_security_findings',
        'ai_security_finding_reviews'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
            table_name
        );
    END LOOP;
END
$rls$;


-- source: V46__ai_security_azure_credentials.sql
CREATE TABLE IF NOT EXISTS ai_security_azure_credential_profiles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    name varchar(255) NOT NULL,
    auth_type varchar(32) NOT NULL,
    azure_tenant_id varchar(128) NOT NULL,
    client_id varchar(255),
    active_secret_ciphertext text,
    pending_secret_ciphertext text,
    active_secret_expires_at timestamptz,
    pending_secret_expires_at timestamptz,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    last_verified_at timestamptz,
    last_verification_status varchar(32),
    expiry_warning_days integer,
    created_by varchar(255) NOT NULL,
    updated_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by varchar(255),
    CONSTRAINT ai_security_azure_credential_auth_check
        CHECK (auth_type IN ('CLIENT_SECRET', 'WORKLOAD_FEDERATION', 'MANAGED_IDENTITY')),
    CONSTRAINT ai_security_azure_credential_status_check
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    UNIQUE (tenant_id, name)
);

ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS credential_profile_id uuid
        REFERENCES ai_security_azure_credential_profiles(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS source_config_id uuid,
    ADD COLUMN IF NOT EXISTS source_target_id uuid,
    ADD COLUMN IF NOT EXISTS provider_tenant_id varchar(128),
    ADD COLUMN IF NOT EXISTS resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_ai_security_azure_credentials_expiry
    ON ai_security_azure_credential_profiles (status, active_secret_expires_at);
CREATE INDEX IF NOT EXISTS idx_ai_security_connector_provider_target
    ON ai_security_connector_configs (provider, source_target_id);

ALTER TABLE ai_security_azure_credential_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_security_azure_credential_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_security_azure_credential_profiles;
CREATE POLICY tenant_isolation ON ai_security_azure_credential_profiles
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);


-- source: V47__ai_security_azure_foundry_endpoint.sql
ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS foundry_endpoint_url varchar(500);


-- source: V48__ai_grid_r0_foundation.sql
-- AI Grid R0: immutable evidence, governed assessment state, and canonical findings.

-- Existing AI assessment and inventory rows are demo data. Connector configuration and
-- encrypted credentials are deliberately retained so inventory can be rebuilt by re-scan.
DELETE FROM ai_security_finding_reviews;
DELETE FROM ai_security_findings;
DELETE FROM ai_security_policy_evaluations;
DELETE FROM ai_security_policy_settings;
DELETE FROM ai_security_relationships;
DELETE FROM ai_security_artifact_sources;
DELETE FROM ai_security_artifacts;
DELETE FROM ai_security_observation_receipts;
DELETE FROM ai_security_snapshot_scopes;

CREATE TABLE IF NOT EXISTS ai_grid_snapshot_bodies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    content_hash varchar(64) NOT NULL,
    content_json jsonb NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    redaction_profile varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, content_hash)
);

CREATE TABLE IF NOT EXISTS ai_grid_snapshot_manifests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    scope_key varchar(512) NOT NULL,
    body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id),
    schema_version varchar(32) NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, artifact_id, scope_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    fact_key varchar(255) NOT NULL,
    value_type varchar(32) NOT NULL,
    value_json jsonb,
    state varchar(32) NOT NULL CHECK (state IN ('KNOWN','UNKNOWN','ERROR','STALE')),
    provenance varchar(32) NOT NULL,
    evidence_class varchar(32) NOT NULL,
    source varchar(255) NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_until timestamptz,
    confidence_method varchar(128),
    confidence_method_version varchar(32),
    confidence double precision CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    derivation_inputs_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    fact_schema_version varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, artifact_id, fact_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_artifact_classifications (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    technology_id varchar(128) NOT NULL,
    capability varchar(128),
    primary_technology boolean NOT NULL DEFAULT false,
    state varchar(32) NOT NULL,
    registry_version varchar(32) NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    classified_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, artifact_id, technology_id, capability)
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_selections (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    selection varchar(32) NOT NULL CHECK (selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    updated_by varchar(255) NOT NULL,
    reason text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_selection_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    policy_id varchar(128) NOT NULL,
    previous_selection varchar(32),
    selection varchar(32) NOT NULL,
    actor varchar(255) NOT NULL,
    reason text,
    changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_assessments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    subject_type varchar(32) NOT NULL,
    subject_id uuid NOT NULL,
    snapshot_manifest_id uuid REFERENCES ai_grid_snapshot_manifests(id),
    selection varchar(32) NOT NULL,
    applicability varchar(32) NOT NULL,
    evidence_readiness varchar(32) NOT NULL,
    decision varchar(32) NOT NULL,
    reason_code varchar(128) NOT NULL,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint varchar(64) NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id, subject_type, subject_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_coverage_gaps (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fingerprint varchar(64) NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    policy_id varchar(128),
    state varchar(64) NOT NULL,
    reason text NOT NULL,
    required_action text,
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS ai_grid_systems (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    stable_key varchar(64) NOT NULL,
    name varchar(512) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    current_revision integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, stable_key)
);

CREATE TABLE IF NOT EXISTS ai_grid_system_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    revision integer NOT NULL,
    membership_hash varchar(64) NOT NULL,
    source varchar(32) NOT NULL,
    rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, system_id, revision),
    UNIQUE (tenant_id, system_id, membership_hash)
);

CREATE TABLE IF NOT EXISTS ai_grid_system_memberships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_revision_id uuid NOT NULL REFERENCES ai_grid_system_revisions(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    membership_state varchar(32) NOT NULL,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, system_revision_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_type varchar(64) NOT NULL,
    aggregate_type varchar(64) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version varchar(64) NOT NULL,
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    status varchar(32) NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_type, aggregate_id, aggregate_version)
);

-- Generalize the canonical host finding without changing existing vulnerability rows.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS uk_findings_component_vulnerability;
ALTER TABLE findings ALTER COLUMN asset_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN component_id DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN vulnerability_id DROP NOT NULL;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_creation_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_creation_source_check
    CHECK (creation_source IN ('MANUAL','AUTOMATIC','AI_SECURITY'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_kind varchar(32) NOT NULL DEFAULT 'VULNERABILITY';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint varchar(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_class varchar(32);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS title varchar(512);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_id varchar(128);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_version varchar(32);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reason_code varchar(128);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assessment_id uuid;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_kind_check;
ALTER TABLE findings ADD CONSTRAINT findings_kind_check
    CHECK (finding_kind IN ('VULNERABILITY','AI_POSTURE','AI_EXPOSURE'));
CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_component_vulnerability
    ON findings (component_id, vulnerability_id)
    WHERE finding_kind = 'VULNERABILITY';
CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_tenant_fingerprint
    ON findings (tenant_id, fingerprint)
    WHERE fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS finding_subjects (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    subject_type varchar(32) NOT NULL,
    subject_id uuid NOT NULL,
    subject_revision varchar(64),
    subject_role varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, finding_id, subject_type, subject_id, subject_role)
);

CREATE TABLE IF NOT EXISTS finding_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL,
    reason text,
    policy_version varchar(32),
    reviewed_by varchar(255) NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_facts_current ON ai_grid_facts (artifact_id, fact_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_assessments_run ON ai_grid_assessments (run_id, decision);
CREATE INDEX IF NOT EXISTS idx_ai_grid_gaps_status ON ai_grid_coverage_gaps (status, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_outbox_work ON ai_grid_outbox (status, available_at, created_at);
CREATE INDEX IF NOT EXISTS idx_finding_subjects_subject ON finding_subjects (subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_finding ON finding_reviews (finding_id, reviewed_at DESC);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_snapshot_bodies', 'ai_grid_snapshot_manifests', 'ai_grid_facts',
        'ai_grid_artifact_classifications', 'ai_grid_policy_selections',
        'ai_grid_policy_selection_history', 'ai_grid_assessments', 'ai_grid_coverage_gaps',
        'ai_grid_systems', 'ai_grid_system_revisions', 'ai_grid_system_memberships',
        'ai_grid_outbox', 'finding_subjects', 'finding_reviews'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                       table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;


-- source: V49__ai_grid_r1_ownership_and_economics.sql
-- AI Grid R1: explicit owner states and per-run evidence economics.

ALTER TABLE ai_security_artifacts
    ADD COLUMN IF NOT EXISTS owner_name varchar(255),
    ADD COLUMN IF NOT EXISTS owner_state varchar(32) NOT NULL DEFAULT 'UNOWNED',
    ADD COLUMN IF NOT EXISTS owner_source varchar(64),
    ADD COLUMN IF NOT EXISTS owner_confidence double precision,
    ADD COLUMN IF NOT EXISTS owner_confidence_method varchar(128),
    ADD COLUMN IF NOT EXISTS owner_confidence_method_version varchar(32),
    ADD COLUMN IF NOT EXISTS owner_updated_at timestamptz,
    ADD COLUMN IF NOT EXISTS business_criticality varchar(32),
    ADD COLUMN IF NOT EXISTS environment varchar(64);

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_owner_state_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_owner_state_check
    CHECK (owner_state IN ('CONFIRMED','INFERRED','CANDIDATE','UNOWNED'));
ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_owner_confidence_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_owner_confidence_check
    CHECK (owner_confidence IS NULL OR (owner_confidence >= 0 AND owner_confidence <= 1));

ALTER TABLE ai_grid_snapshot_bodies ADD COLUMN IF NOT EXISTS first_run_id uuid;

CREATE TABLE IF NOT EXISTS ai_grid_owner_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    previous_owner_name varchar(255),
    previous_owner_state varchar(32),
    owner_name varchar(255),
    owner_state varchar(32) NOT NULL,
    owner_source varchar(64),
    confidence double precision,
    confidence_method varchar(128),
    confidence_method_version varchar(32),
    actor varchar(255) NOT NULL,
    reason text,
    changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_run_metrics (
    run_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    completed_scope_count bigint NOT NULL DEFAULT 0,
    processing_duration_ms bigint NOT NULL DEFAULT 0,
    provider_api_calls bigint,
    provider_call_measurement_state varchar(32) NOT NULL DEFAULT 'UNAVAILABLE',
    artifact_count bigint NOT NULL DEFAULT 0,
    snapshot_manifest_count bigint NOT NULL DEFAULT 0,
    snapshot_bytes bigint NOT NULL DEFAULT 0,
    new_snapshot_bytes bigint NOT NULL DEFAULT 0,
    fact_count bigint NOT NULL DEFAULT 0,
    assessment_count bigint NOT NULL DEFAULT 0,
    pass_count bigint NOT NULL DEFAULT 0,
    fail_count bigint NOT NULL DEFAULT 0,
    no_decision_count bigint NOT NULL DEFAULT 0,
    open_gap_count bigint NOT NULL DEFAULT 0,
    first_inventory_at timestamptz,
    first_decision_at timestamptz,
    first_finding_at timestamptz,
    first_gap_at timestamptz,
    first_recorded_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_run_scope_metrics (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    scope_key varchar(512) NOT NULL,
    processing_duration_ms bigint NOT NULL CHECK (processing_duration_ms >= 0),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, scope_key)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_owner_history_artifact
    ON ai_grid_owner_history (artifact_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_run_metrics_updated
    ON ai_grid_run_metrics (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_run_scope_metrics_run
    ON ai_grid_run_scope_metrics (run_id);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_owner_history', 'ai_grid_run_metrics', 'ai_grid_run_scope_metrics'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                       table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;


-- source: V50__ai_grid_budgets_retention_and_provider_metrics.sql
-- AI Grid R1: enforceable scan budgets, cadence, evidence retention, and provider-call accounting.

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS provider varchar(32),
    ADD COLUMN IF NOT EXISTS retained_snapshot_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS budget_state varchar(32) NOT NULL DEFAULT 'WITHIN_BUDGET';

ALTER TABLE ai_grid_snapshot_bodies
    ADD COLUMN IF NOT EXISTS retention_class varchar(32) NOT NULL DEFAULT 'HOT',
    ADD COLUMN IF NOT EXISTS retain_until timestamptz NOT NULL DEFAULT (now() + interval '90 days'),
    ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS replay_commitment_until timestamptz,
    ADD COLUMN IF NOT EXISTS retention_state varchar(32) NOT NULL DEFAULT 'RETAINED';

CREATE TABLE IF NOT EXISTS ai_grid_budget_config (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    enforcement_mode varchar(32) NOT NULL DEFAULT 'OBSERVE',
    daily_scan_limit bigint,
    daily_provider_api_call_limit bigint,
    daily_new_snapshot_bytes_limit bigint,
    daily_processing_ms_limit bigint,
    retained_snapshot_bytes_limit bigint,
    warning_ratio double precision NOT NULL DEFAULT 0.80,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (enforcement_mode IN ('OBSERVE','THROTTLE')),
    CHECK (daily_scan_limit IS NULL OR daily_scan_limit > 0),
    CHECK (daily_provider_api_call_limit IS NULL OR daily_provider_api_call_limit > 0),
    CHECK (daily_new_snapshot_bytes_limit IS NULL OR daily_new_snapshot_bytes_limit > 0),
    CHECK (daily_processing_ms_limit IS NULL OR daily_processing_ms_limit > 0),
    CHECK (retained_snapshot_bytes_limit IS NULL OR retained_snapshot_bytes_limit > 0),
    CHECK (warning_ratio > 0 AND warning_ratio < 1)
);

INSERT INTO ai_grid_budget_config
    (tenant_id, enforcement_mode, daily_scan_limit, daily_provider_api_call_limit,
     daily_new_snapshot_bytes_limit, daily_processing_ms_limit, retained_snapshot_bytes_limit,
     warning_ratio, updated_by, reason)
VALUES ('${tenantId}'::uuid, 'OBSERVE', 24, 10000, 1073741824, 3600000, 10737418240,
        0.80, 'ai-grid-bootstrap', 'Initial observable AI Grid budget')
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS ai_grid_scan_cadence_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(32) NOT NULL,
    resource_family varchar(128) NOT NULL DEFAULT '*',
    environment varchar(64) NOT NULL DEFAULT '*',
    criticality varchar(32) NOT NULL DEFAULT '*',
    minimum_interval_seconds bigint NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, resource_family, environment, criticality),
    CHECK (minimum_interval_seconds >= 0)
);

CREATE TABLE IF NOT EXISTS ai_grid_budget_admissions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    resource_families_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    decision varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    usage_json jsonb NOT NULL,
    admitted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id),
    CHECK (decision IN ('ADMITTED','THROTTLED'))
);

CREATE TABLE IF NOT EXISTS ai_grid_budget_alerts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid,
    metric varchar(64) NOT NULL,
    level varchar(32) NOT NULL,
    observed_value bigint NOT NULL,
    limit_value bigint NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_by varchar(255),
    acknowledged_at timestamptz,
    CHECK (level IN ('WARNING','EXCEEDED')),
    CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED'))
);

CREATE TABLE IF NOT EXISTS ai_grid_retention_policies (
    retention_class varchar(32) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    retain_days integer NOT NULL,
    archive_after_days integer,
    restricted boolean NOT NULL DEFAULT false,
    updated_by varchar(255) NOT NULL,
    reason text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (retention_class IN ('HOT','ARCHIVE','RESTRICTED_EVIDENCE')),
    CHECK (retain_days > 0),
    CHECK (archive_after_days IS NULL OR (archive_after_days >= 0 AND archive_after_days < retain_days))
);

INSERT INTO ai_grid_retention_policies
    (retention_class, tenant_id, retain_days, archive_after_days, restricted, updated_by, reason)
VALUES
    ('HOT', '${tenantId}'::uuid, 90, 30, false, 'ai-grid-bootstrap', 'Default replay retention'),
    ('ARCHIVE', '${tenantId}'::uuid, 365, null, false, 'ai-grid-bootstrap', 'Extended archive retention'),
    ('RESTRICTED_EVIDENCE', '${tenantId}'::uuid, 30, null, true, 'ai-grid-bootstrap', 'Restricted evidence retention')
ON CONFLICT (retention_class) DO NOTHING;

CREATE TABLE IF NOT EXISTS ai_grid_evidence_holds (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id) ON DELETE CASCADE,
    hold_type varchar(32) NOT NULL,
    reference_id varchar(255) NOT NULL,
    reason text NOT NULL,
    expires_at timestamptz,
    released_at timestamptz,
    released_by varchar(255),
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, snapshot_body_id, hold_type, reference_id),
    CHECK (hold_type IN ('ACTIVE_FINDING','EXCEPTION','LEGAL_HOLD','REPLAY_COMMITMENT'))
);

CREATE TABLE IF NOT EXISTS ai_grid_retention_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL REFERENCES ai_grid_snapshot_bodies(id) ON DELETE CASCADE,
    decision varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, snapshot_body_id, evaluated_at),
    CHECK (decision IN ('RETAIN','ARCHIVE','PURGE_BLOCKED','PURGE_ELIGIBLE'))
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_admissions_day
    ON ai_grid_budget_admissions (admitted_at DESC, provider);
CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_alerts_open
    ON ai_grid_budget_alerts (status, level);
CREATE UNIQUE INDEX IF NOT EXISTS uk_ai_grid_budget_alert_open_metric
    ON ai_grid_budget_alerts (tenant_id, metric)
    WHERE status IN ('OPEN','ACKNOWLEDGED');
CREATE INDEX IF NOT EXISTS idx_ai_grid_snapshot_retention
    ON ai_grid_snapshot_bodies (retention_state, retain_until);
CREATE INDEX IF NOT EXISTS idx_ai_grid_evidence_holds_body
    ON ai_grid_evidence_holds (snapshot_body_id, released_at, expires_at);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_budget_config', 'ai_grid_scan_cadence_rules', 'ai_grid_budget_admissions',
        'ai_grid_budget_alerts', 'ai_grid_retention_policies', 'ai_grid_evidence_holds',
        'ai_grid_retention_decisions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid', table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;


-- source: V51__ai_grid_r0_integrity_hardening.sql
-- AI Grid R0 integrity hardening: deterministic decisions and host-finding invariants.

ALTER TABLE ai_grid_assessments
    ADD COLUMN IF NOT EXISTS evaluation_as_of timestamptz,
    ADD COLUMN IF NOT EXISTS decision_fingerprint varchar(64);

UPDATE ai_grid_assessments
SET evaluation_as_of = evaluated_at
WHERE evaluation_as_of IS NULL;

ALTER TABLE ai_grid_assessments
    ALTER COLUMN evaluation_as_of SET NOT NULL;

CREATE TABLE IF NOT EXISTS ai_grid_relationship_snapshots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    source_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    target_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    relationship_type varchar(128) NOT NULL,
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, run_id, source_artifact_id, target_artifact_id, relationship_type)
);

ALTER TABLE ai_grid_relationship_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_relationship_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_relationship_snapshots;
CREATE POLICY tenant_isolation ON ai_grid_relationship_snapshots
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_ai_grid_relationship_snapshots_source
    ON ai_grid_relationship_snapshots (run_id, source_artifact_id, relationship_type);

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_vulnerability_subject_check;
ALTER TABLE findings ADD CONSTRAINT findings_vulnerability_subject_check CHECK (
    finding_kind <> 'VULNERABILITY'
    OR (
        vulnerability_id IS NOT NULL
        AND (asset_id IS NOT NULL OR component_id IS NOT NULL)
    )
);


-- source: V52__ai_grid_r1_readiness_and_first_run.sql
-- R1 managed-AI readiness, structured setup actions, and first-run utility telemetry.

ALTER TABLE ai_grid_snapshot_manifests
    ADD COLUMN IF NOT EXISTS connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_ai_grid_snapshot_manifest_connector
    ON ai_grid_snapshot_manifests (connector_config_id, created_at, run_id);

CREATE TABLE IF NOT EXISTS ai_grid_policy_readiness (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    selection varchar(32) NOT NULL,
    readiness varchar(32) NOT NULL,
    candidate_count bigint NOT NULL DEFAULT 0,
    applicable_count bigint NOT NULL DEFAULT 0,
    decision_required_count bigint NOT NULL DEFAULT 0,
    decision_ready_count bigint NOT NULL DEFAULT 0,
    no_decision_count bigint NOT NULL DEFAULT 0,
    error_count bigint NOT NULL DEFAULT 0,
    missing_assessment_count bigint NOT NULL DEFAULT 0,
    required_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    available_facts_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    computed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, run_id, policy_id),
    CHECK (selection IN ('REQUIRED','ENABLED','PREVIEW','DISABLED')),
    CHECK (readiness IN ('READY','PARTIAL','BLOCKED','NOT_APPLICABLE','NO_RESOURCES'))
);

CREATE TABLE IF NOT EXISTS ai_grid_setup_actions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    policy_id varchar(128),
    fingerprint varchar(64) NOT NULL,
    priority integer NOT NULL,
    category varchar(32) NOT NULL,
    action_code varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    detail text NOT NULL,
    evidence_key varchar(512),
    status varchar(32) NOT NULL DEFAULT 'OPEN',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, fingerprint),
    CHECK (priority BETWEEN 1 AND 100),
    CHECK (status IN ('OPEN','RESOLVED'))
);

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS connector_config_id uuid REFERENCES ai_security_connector_configs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS expected_assessment_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS missing_assessment_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS decision_reachable_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_expected_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_decision_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS decision_reachability_percent double precision NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS owner_facing_utility_percent double precision NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS baseline_run boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS first_run_target_percent double precision NOT NULL DEFAULT 80,
    ADD COLUMN IF NOT EXISTS first_run_target_met boolean,
    ADD COLUMN IF NOT EXISTS first_owner_routed_finding_at timestamptz,
    ADD COLUMN IF NOT EXISTS first_exposure_hypothesis_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_readiness_run
    ON ai_grid_policy_readiness (run_id, selection, readiness);
CREATE INDEX IF NOT EXISTS idx_ai_grid_setup_actions_open
    ON ai_grid_setup_actions (run_id, status, priority, category);

ALTER TABLE ai_grid_policy_readiness ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_policy_readiness FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_policy_readiness;
CREATE POLICY tenant_isolation ON ai_grid_policy_readiness
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ai_grid_setup_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_setup_actions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_setup_actions;
CREATE POLICY tenant_isolation ON ai_grid_setup_actions
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);


-- source: V53__ai_grid_current_coverage_epoch.sql
-- R1: materialized multi-provider current coverage and dimensional reporting.

CREATE TABLE IF NOT EXISTS ai_grid_current_coverage_state (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    scope_head_count bigint NOT NULL DEFAULT 0,
    artifact_count bigint NOT NULL DEFAULT 0,
    candidate_count bigint NOT NULL DEFAULT 0,
    materialized_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_current_coverage_artifacts (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    technology_id varchar(128) NOT NULL DEFAULT 'UNCLASSIFIED',
    environment varchar(64) NOT NULL DEFAULT 'UNSPECIFIED',
    owner_name varchar(255) NOT NULL DEFAULT 'UNOWNED',
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_current_expected_candidates (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    source_run_id uuid NOT NULL,
    snapshot_manifest_id uuid NOT NULL REFERENCES ai_grid_snapshot_manifests(id) ON DELETE CASCADE,
    provider varchar(32) NOT NULL,
    account_id varchar(64) NOT NULL,
    region varchar(64) NOT NULL,
    resource_family varchar(128) NOT NULL,
    artifact_type varchar(64) NOT NULL,
    native_kind varchar(128) NOT NULL,
    technology_id varchar(128) NOT NULL,
    environment varchar(64) NOT NULL,
    owner_name varchar(255) NOT NULL,
    policy_id varchar(128) NOT NULL,
    policy_version varchar(32) NOT NULL,
    selection varchar(32) NOT NULL,
    framework_mappings_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    assessment_id uuid,
    applicability varchar(32),
    evidence_readiness varchar(32),
    decision varchar(32),
    missing_evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_facts_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, artifact_id, policy_id)
);

ALTER TABLE ai_grid_policy_readiness ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;
ALTER TABLE ai_grid_coverage_gaps ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;
ALTER TABLE ai_grid_setup_actions ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;

CREATE INDEX IF NOT EXISTS idx_ai_grid_current_artifacts_epoch
    ON ai_grid_current_coverage_artifacts (epoch_id, provider, resource_family);
CREATE INDEX IF NOT EXISTS idx_ai_grid_current_candidates_epoch
    ON ai_grid_current_expected_candidates (epoch_id, provider, resource_family, policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_readiness_epoch
    ON ai_grid_policy_readiness (coverage_epoch_id, selection, readiness);
CREATE INDEX IF NOT EXISTS idx_ai_grid_coverage_gaps_epoch
    ON ai_grid_coverage_gaps (coverage_epoch_id, status, state);
CREATE INDEX IF NOT EXISTS idx_ai_grid_setup_actions_epoch
    ON ai_grid_setup_actions (coverage_epoch_id, status, priority);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_current_coverage_state',
        'ai_grid_current_coverage_artifacts',
        'ai_grid_current_expected_candidates'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
                       table_name, '${tenantId}');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;


-- source: V54__ai_grid_budget_admission_scope.sql
-- Preserve the scope dimensions used when a cadence admission is decided.
ALTER TABLE ai_grid_budget_admissions
    ADD COLUMN IF NOT EXISTS environment varchar(64) NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS criticality varchar(32) NOT NULL DEFAULT '*';

CREATE INDEX IF NOT EXISTS idx_ai_grid_budget_admission_cadence
    ON ai_grid_budget_admissions (provider, environment, criticality, admitted_at DESC)
    WHERE decision = 'ADMITTED';


-- source: V55__ai_grid_retention_purge_audit.sql
-- Durable audit survives deletion of an unreferenced snapshot body.
CREATE TABLE IF NOT EXISTS ai_grid_retention_purge_audit (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_body_id uuid NOT NULL,
    content_hash varchar(64) NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    reason_code varchar(64) NOT NULL,
    purged_by varchar(255) NOT NULL,
    purged_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_retention_purge_audit_time
    ON ai_grid_retention_purge_audit (purged_at DESC);

ALTER TABLE ai_grid_retention_purge_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_retention_purge_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_retention_purge_audit;
CREATE POLICY tenant_isolation ON ai_grid_retention_purge_audit
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);


-- source: V56__ai_grid_r2_exposure_management.sql
-- AI Grid R2: system lifecycle, host context ports, and bounded exposure correlation.

ALTER TABLE ai_grid_relationship_snapshots
    ADD COLUMN IF NOT EXISTS valid_from timestamptz,
    ADD COLUMN IF NOT EXISTS valid_until timestamptz;
UPDATE ai_grid_relationship_snapshots SET valid_from = observed_at WHERE valid_from IS NULL;
ALTER TABLE ai_grid_relationship_snapshots ALTER COLUMN valid_from SET NOT NULL;
ALTER TABLE ai_grid_relationship_snapshots ALTER COLUMN valid_from SET DEFAULT now();

ALTER TABLE ai_grid_systems
    ADD COLUMN IF NOT EXISTS root_artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS retired_at timestamptz;
ALTER TABLE ai_grid_system_revisions
    ADD COLUMN IF NOT EXISTS run_id uuid,
    ADD COLUMN IF NOT EXISTS valid_from timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_until timestamptz;
DO $drop_membership_hash_unique$
DECLARE constraint_name text;
BEGIN
    SELECT conname INTO constraint_name FROM pg_constraint
     WHERE conrelid='ai_grid_system_revisions'::regclass AND contype='u'
       AND pg_get_constraintdef(oid) LIKE '%membership_hash%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE ai_grid_system_revisions DROP CONSTRAINT %I', constraint_name);
    END IF;
END $drop_membership_hash_unique$;
ALTER TABLE ai_grid_system_memberships
    ADD COLUMN IF NOT EXISTS valid_from timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_until timestamptz,
    ADD COLUMN IF NOT EXISTS decided_by varchar(255),
    ADD COLUMN IF NOT EXISTS decided_at timestamptz;

CREATE TABLE IF NOT EXISTS ai_grid_system_lineage_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_type varchar(32) NOT NULL CHECK (event_type IN ('SPLIT','MERGED','RETIRED','SUCCESSOR')),
    run_id uuid,
    rationale text NOT NULL,
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_grid_system_membership_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    resulting_revision_id uuid NOT NULL REFERENCES ai_grid_system_revisions(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    decision varchar(16) NOT NULL CHECK (decision IN ('ACCEPT','REJECT')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_grid_system_lineage_participants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    event_id uuid NOT NULL REFERENCES ai_grid_system_lineage_events(id) ON DELETE CASCADE,
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id) ON DELETE SET NULL,
    participant_role varchar(16) NOT NULL CHECK (participant_role IN ('PREDECESSOR','SUCCESSOR')),
    UNIQUE (tenant_id, event_id, system_id, participant_role)
);

CREATE TABLE IF NOT EXISTS ai_grid_host_context_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    fact_key varchar(255) NOT NULL,
    value_type varchar(32) NOT NULL,
    value_json jsonb,
    state varchar(32) NOT NULL CHECK (state IN ('KNOWN','UNKNOWN','ERROR','STALE')),
    provenance varchar(32) NOT NULL,
    evidence_class varchar(32) NOT NULL,
    source_port varchar(32) NOT NULL CHECK (source_port IN ('IDENTITY','DATA','REACHABILITY','ASSET','OWNERSHIP')),
    evidence_reference varchar(1024) NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, artifact_id, fact_key, source_port, observed_at)
);

CREATE TABLE IF NOT EXISTS ai_grid_exposure_paths (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fingerprint varchar(64) NOT NULL,
    correlation_id varchar(128) NOT NULL,
    correlation_version varchar(32) NOT NULL,
    root_cause_artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id),
    canonical_path_signature varchar(64) NOT NULL,
    state varchar(32) NOT NULL CHECK (state IN ('EXPOSURE_HYPOTHESIS','VALIDATED_EXPOSURE','CLOSED')),
    status varchar(32) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
    severity varchar(32) NOT NULL,
    title varchar(512) NOT NULL,
    impact text NOT NULL,
    root_cause text NOT NULL,
    breakpoint text NOT NULL,
    confidence_method varchar(128) NOT NULL,
    confidence_method_version varchar(32) NOT NULL,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    validated_at timestamptz,
    closed_at timestamptz,
    last_complete_run_id uuid NOT NULL,
    finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    run_id uuid NOT NULL,
    state varchar(32) NOT NULL CHECK (state IN ('EXPOSURE_HYPOTHESIS','VALIDATED_EXPOSURE','ABSENT')),
    entry_artifact_id uuid REFERENCES ai_security_artifacts(id),
    system_id uuid REFERENCES ai_grid_systems(id),
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id),
    path_json jsonb NOT NULL,
    evidence_json jsonb NOT NULL,
    temporal_valid_from timestamptz NOT NULL,
    temporal_valid_until timestamptz,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, exposure_path_id, run_id)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_associations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    system_id uuid REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    system_revision_id uuid REFERENCES ai_grid_system_revisions(id) ON DELETE SET NULL,
    artifact_id uuid REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    association_role varchar(32) NOT NULL CHECK (association_role IN ('AFFECTED_SYSTEM','ENTRY_POINT','IMPACT','ROOT_CAUSE')),
    UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, system_id, artifact_id, association_role)
);
CREATE TABLE IF NOT EXISTS ai_grid_exposure_dispositions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    exposure_path_id uuid NOT NULL REFERENCES ai_grid_exposure_paths(id) ON DELETE CASCADE,
    disposition varchar(32) NOT NULL CHECK (disposition IN ('ACCEPTED','REJECTED','RISK_ACCEPTED','NEEDS_EVIDENCE')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_current ON ai_grid_exposure_paths (status, state, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_observation_run ON ai_grid_exposure_observations (run_id, state);
CREATE INDEX IF NOT EXISTS idx_ai_grid_host_context_current ON ai_grid_host_context_facts (artifact_id, fact_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_lineage_system ON ai_grid_system_lineage_participants (system_id, participant_role);

ALTER TABLE ai_grid_run_metrics
    ADD COLUMN IF NOT EXISTS graph_recomputed_node_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_recomputed_edge_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_traversed_path_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS exposure_path_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS graph_recompute_duration_ms bigint NOT NULL DEFAULT 0;

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_system_lineage_events', 'ai_grid_system_lineage_participants',
        'ai_grid_system_membership_decisions',
        'ai_grid_host_context_facts', 'ai_grid_exposure_paths',
        'ai_grid_exposure_observations', 'ai_grid_exposure_associations',
        'ai_grid_exposure_dispositions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END $rls$;


-- source: V57__ai_grid_r2_completion_hardening.sql
-- Complete R2 temporal replay, durable membership decisions, and correlation epochs.

ALTER TABLE ai_grid_system_revisions
    ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid;

ALTER TABLE ai_grid_exposure_paths
    ADD COLUMN IF NOT EXISTS last_complete_epoch_id uuid;

ALTER TABLE ai_grid_exposure_observations
    ADD COLUMN IF NOT EXISTS coverage_epoch_id uuid,
    ADD COLUMN IF NOT EXISTS correlation_material_digest varchar(64);
DO $drop_observation_run_unique$
DECLARE constraint_name text;
BEGIN
    SELECT conname INTO constraint_name FROM pg_constraint
     WHERE conrelid='ai_grid_exposure_observations'::regclass AND contype='u'
       AND pg_get_constraintdef(oid) LIKE '%exposure_path_id%run_id%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE ai_grid_exposure_observations DROP CONSTRAINT %I', constraint_name);
    END IF;
END $drop_observation_run_unique$;
ALTER TABLE ai_grid_exposure_observations
    ADD CONSTRAINT uq_ai_grid_exposure_observation_epoch
    UNIQUE NULLS NOT DISTINCT (tenant_id, exposure_path_id, run_id, coverage_epoch_id);

CREATE TABLE IF NOT EXISTS ai_grid_system_membership_overrides (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    system_id uuid NOT NULL REFERENCES ai_grid_systems(id) ON DELETE CASCADE,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    decision varchar(16) NOT NULL CHECK (decision IN ('ACCEPT','REJECT')),
    reason text NOT NULL,
    actor varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, system_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_exposure_executions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    coverage_epoch_id uuid NOT NULL,
    trigger_run_id uuid NOT NULL,
    evaluation_as_of timestamptz NOT NULL,
    correlation_versions_json jsonb NOT NULL,
    artifact_bindings_json jsonb NOT NULL,
    relationship_ids_json jsonb NOT NULL,
    host_fact_ids_json jsonb NOT NULL,
    system_revision_ids_json jsonb NOT NULL,
    material_digest varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, coverage_epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_execution_run
    ON ai_grid_exposure_executions (trigger_run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_grid_system_revision_epoch
    ON ai_grid_system_revisions (coverage_epoch_id, system_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_exposure_observation_epoch
    ON ai_grid_exposure_observations (coverage_epoch_id, exposure_path_id);

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_grid_system_membership_overrides', 'ai_grid_exposure_executions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END $rls$;


-- source: V58__ai_security_policy_scope.sql
CREATE TABLE IF NOT EXISTS ai_security_policy_scopes (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    mode varchar(32) NOT NULL DEFAULT 'ALL',
    condition_logic varchar(8) NOT NULL DEFAULT 'AND',
    conditions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_security_policy_artifact_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    policy_id varchar(128) NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    override varchar(16) NOT NULL,
    reason text,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_security_policy_parameters (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_security_policy_overrides_policy
    ON ai_security_policy_artifact_overrides (policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_security_policy_overrides_artifact
    ON ai_security_policy_artifact_overrides (artifact_id);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ai_security_policy_scopes',
        'ai_security_policy_artifact_overrides',
        'ai_security_policy_parameters'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
            table_name
        );
    END LOOP;
END
$rls$;


-- source: V59__ai_grid_trusted_evidence_producers.sql
ALTER TABLE ai_grid_host_context_facts
    ADD COLUMN IF NOT EXISTS producer_id varchar(128) NOT NULL DEFAULT 'LEGACY_UNBOUND';

CREATE INDEX IF NOT EXISTS idx_ai_grid_host_context_producer
    ON ai_grid_host_context_facts (producer_id, confidence_method_version, observed_at DESC);


-- source: V60__migrate_legacy_ai_findings_to_canonical.sql
-- Retire the legacy AI findings silo without losing any records created before AI Grid.
-- Canonical findings keep the original UUID so review history can be carried across.

INSERT INTO findings (
    id, tenant_id, finding_kind, fingerprint, workflow_class, status, decision_state,
    creation_source, matched_by, confidence_score, first_observed_at, last_observed_at,
    closed_at, closed_reason, display_id, title, policy_id, policy_version, severity_override,
    risk_score, evidence, reason_code, created_at, updated_at
)
SELECT f.id,
       f.tenant_id,
       'AI_POSTURE',
       md5(f.tenant_id::text || '|AI_POSTURE|' || f.policy_id || '|' || f.artifact_id::text),
       'POSTURE_FINDING',
       CASE WHEN f.status = 'OPEN' THEN 'OPEN' ELSE 'AUTO_CLOSED' END,
       CASE WHEN f.status = 'OPEN' THEN 'AFFECTED' ELSE 'NOT_AFFECTED' END,
       'AI_SECURITY',
       'legacy-ai-migration',
       1.0,
       f.first_observed_at,
       f.last_observed_at,
       CASE WHEN f.status = 'OPEN' THEN NULL ELSE coalesce(f.resolved_at, f.last_observed_at, now()) END,
       CASE WHEN f.status = 'OPEN' THEN NULL ELSE 'AUTO_POLICY_NOT_OWNER_FACING' END,
       'F-' || upper(substr(replace(f.id::text, '-', ''), 1, 12)),
       f.title,
       f.policy_id,
       f.policy_version,
       f.severity,
       CASE f.severity WHEN 'CRITICAL' THEN 9.5 WHEN 'HIGH' THEN 8.0
                       WHEN 'MEDIUM' THEN 5.0 ELSE 2.0 END,
       f.evidence_json,
       'LEGACY_AI_MIGRATION',
       f.first_observed_at,
       f.last_observed_at
  FROM ai_security_findings f
 WHERE NOT EXISTS (select 1 from findings existing where existing.id = f.id)
ON CONFLICT (id) DO NOTHING;

INSERT INTO finding_subjects (id, finding_id, tenant_id, subject_type, subject_id, subject_role)
SELECT gen_random_uuid(), f.id, f.tenant_id, 'ARTIFACT', f.artifact_id, 'PRIMARY'
  FROM ai_security_findings f
 WHERE NOT EXISTS (
           select 1 from finding_subjects subject
            where subject.finding_id = f.id and subject.subject_role = 'PRIMARY'
       )
ON CONFLICT (tenant_id, finding_id, subject_type, subject_id, subject_role) DO NOTHING;

INSERT INTO finding_reviews (id, finding_id, tenant_id, disposition, reason, policy_version, reviewed_by, reviewed_at)
SELECT r.id, r.finding_id, r.tenant_id, r.disposition, r.reason,
       r.policy_version, r.reviewed_by, r.reviewed_at
  FROM ai_security_finding_reviews r
 WHERE EXISTS (select 1 from findings f where f.id = r.finding_id)
ON CONFLICT (id) DO NOTHING;


-- source: V61__ai_grid_policy_legacy_selection_bridge.sql
-- Preserve pre-AI-Grid tenant choices during the staged policy migration.
-- A governed selection always wins if it already exists.
INSERT INTO ai_grid_policy_selections (policy_id, tenant_id, selection, updated_by, reason)
SELECT legacy.policy_id,
       legacy.tenant_id,
       CASE WHEN published.default_selection = 'REQUIRED' THEN 'REQUIRED'
            WHEN legacy.enabled THEN 'ENABLED' ELSE 'DISABLED' END,
       legacy.updated_by,
       'Migrated from legacy ai_security_policy_settings'
  FROM ai_security_policy_settings legacy
  JOIN (
      SELECT DISTINCT ON (policy_id) policy_id, default_selection
        FROM platform.ai_grid_policy_versions
       WHERE lifecycle = 'PUBLISHED'
       ORDER BY policy_id, published_at DESC NULLS LAST, version DESC
  ) published ON published.policy_id = legacy.policy_id
ON CONFLICT (policy_id) DO NOTHING;


-- source: V62__ai_artifact_pii_classification.sql
-- Per-artifact PII classification summary, sourced read-only from AWS Macie / Azure Purview
-- against storage the artifact is already known to read from (READS_FROM_S3 /
-- READS_FROM_STORAGE_ACCOUNT relationships). Scout never scans content itself.

ALTER TABLE ai_security_artifacts
    ADD COLUMN IF NOT EXISTS pii_scan_status varchar(32) NOT NULL DEFAULT 'NOT_APPLICABLE',
    ADD COLUMN IF NOT EXISTS pii_source varchar(32),
    ADD COLUMN IF NOT EXISTS pii_info_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS pii_finding_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pii_last_scanned_at timestamptz;

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_scan_status_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_scan_status_check
    CHECK (pii_scan_status IN ('UNKNOWN','NOT_APPLICABLE','NOT_SCANNED','SCANNED_CLEAN','SCANNED_PII_FOUND','LOOKUP_FAILED'));

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_source_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_source_check
    CHECK (pii_source IS NULL OR pii_source IN ('AWS_MACIE','AZURE_PURVIEW'));

ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_finding_count_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_finding_count_check
    CHECK (pii_finding_count >= 0);


-- source: V63__ai_security_azure_purview_account.sql
-- Purview account name the Azure AI Security connector reads classification results from
-- (read-only Data Map lookups; Scout never creates or runs Purview scans itself).

ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS purview_account_name varchar(255);


-- source: V64__ai_artifact_unknown_sensitivity.sql
-- Missing or incomplete provider evidence is an explicit UNKNOWN state, never a safe default.
ALTER TABLE ai_security_artifacts DROP CONSTRAINT IF EXISTS ai_security_artifacts_pii_scan_status_check;
ALTER TABLE ai_security_artifacts ADD CONSTRAINT ai_security_artifacts_pii_scan_status_check
    CHECK (pii_scan_status IN ('UNKNOWN','NOT_APPLICABLE','NOT_SCANNED','SCANNED_CLEAN','SCANNED_PII_FOUND','LOOKUP_FAILED'));

UPDATE ai_security_artifacts
   SET pii_scan_status = 'UNKNOWN'
 WHERE artifact_type IN ('KNOWLEDGE_BASE','DATA_SOURCE','DATA_STORE','SEARCH_INDEX')
   AND pii_scan_status = 'NOT_APPLICABLE';


-- source: V65__ai_grid_policy_configuration_consolidation.sql
-- AI Grid is the sole owner of tenant policy configuration.  Backfill is
-- deliberately idempotent and rejects configuration for policies that never
-- reached the governed catalog before legacy state is removed.
CREATE TABLE IF NOT EXISTS ai_grid_policy_scopes (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    mode varchar(32) NOT NULL DEFAULT 'ALL',
    condition_logic varchar(8) NOT NULL DEFAULT 'AND',
    conditions_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_artifact_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    policy_id varchar(128) NOT NULL,
    artifact_id uuid NOT NULL REFERENCES ai_security_artifacts(id) ON DELETE CASCADE,
    override varchar(16) NOT NULL,
    reason text,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, policy_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS ai_grid_policy_parameters (
    policy_id varchar(128) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_overrides_policy ON ai_grid_policy_artifact_overrides (policy_id);
CREATE INDEX IF NOT EXISTS idx_ai_grid_policy_overrides_artifact ON ai_grid_policy_artifact_overrides (artifact_id);

DO $rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['ai_grid_policy_scopes', 'ai_grid_policy_artifact_overrides', 'ai_grid_policy_parameters'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$rls$;

INSERT INTO ai_grid_policy_scopes (policy_id, tenant_id, mode, condition_logic, conditions_json, updated_by, updated_at)
SELECT s.policy_id, s.tenant_id, s.mode, s.condition_logic, s.conditions_json, s.updated_by, s.updated_at
  FROM ai_security_policy_scopes s
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id = s.policy_id AND p.lifecycle = 'PUBLISHED')
ON CONFLICT (policy_id) DO NOTHING;

INSERT INTO ai_grid_policy_artifact_overrides (id, tenant_id, policy_id, artifact_id, override, reason, created_by, created_at, updated_at)
SELECT o.id, o.tenant_id, o.policy_id, o.artifact_id, o.override, o.reason, o.created_by, o.created_at, o.updated_at
  FROM ai_security_policy_artifact_overrides o
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id = o.policy_id AND p.lifecycle = 'PUBLISHED')
ON CONFLICT (tenant_id, policy_id, artifact_id) DO NOTHING;

INSERT INTO ai_grid_policy_parameters (policy_id, tenant_id, parameters_json, updated_by, updated_at)
SELECT p.policy_id, p.tenant_id, p.parameters_json, p.updated_by, p.updated_at
  FROM ai_security_policy_parameters p
 WHERE EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions v WHERE v.policy_id = p.policy_id AND v.lifecycle = 'PUBLISHED')
ON CONFLICT (policy_id) DO NOTHING;

DO $migration$
BEGIN
    IF EXISTS (SELECT 1 FROM ai_security_policy_scopes s WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=s.policy_id AND p.lifecycle='PUBLISHED'))
       OR EXISTS (SELECT 1 FROM ai_security_policy_artifact_overrides o WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=o.policy_id AND p.lifecycle='PUBLISHED'))
       OR EXISTS (SELECT 1 FROM ai_security_policy_parameters x WHERE NOT EXISTS (SELECT 1 FROM platform.ai_grid_policy_versions p WHERE p.policy_id=x.policy_id AND p.lifecycle='PUBLISHED')) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI policy configuration with unmapped policy records';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_findings legacy
         LEFT JOIN findings canonical ON canonical.id = legacy.id
         WHERE canonical.id IS NULL
            OR canonical.policy_id IS DISTINCT FROM legacy.policy_id
            OR (legacy.status = 'OPEN' AND canonical.status <> 'OPEN')
            OR (legacy.status <> 'OPEN' AND canonical.status = 'OPEN')
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI findings before canonical finding state is verified';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_finding_reviews legacy
         LEFT JOIN finding_reviews canonical ON canonical.id = legacy.id
         WHERE canonical.id IS NULL
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI finding reviews before canonical review IDs are verified';
    END IF;
    IF EXISTS (
        SELECT 1 FROM ai_security_findings legacy
         WHERE NOT EXISTS (
             SELECT 1 FROM finding_subjects subject
              WHERE subject.finding_id = legacy.id
                AND subject.subject_type = 'ARTIFACT'
                AND subject.subject_id = legacy.artifact_id
                AND subject.subject_role = 'PRIMARY'
         )
    ) THEN
        RAISE EXCEPTION 'Cannot retire legacy AI findings before canonical subjects are verified';
    END IF;
END
$migration$;

DROP TABLE ai_security_policy_artifact_overrides;
DROP TABLE ai_security_policy_parameters;
DROP TABLE ai_security_policy_scopes;
DROP TABLE ai_security_policy_settings;
DROP TABLE ai_security_policy_evaluations;
DROP TABLE ai_security_finding_reviews;
DROP TABLE ai_security_findings;


-- source: V66__ai_grid_capability_observations.sql
CREATE TABLE IF NOT EXISTS ai_grid_capability_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    run_id uuid NOT NULL,
    provider varchar(32) NOT NULL,
    capability_id varchar(128) NOT NULL,
    connector varchar(128) NOT NULL,
    account_id varchar(255) NOT NULL,
    region varchar(128) NOT NULL,
    resource_family varchar(128) NOT NULL,
    connector_version varchar(64),
    observed_at timestamptz NOT NULL,
    expires_at timestamptz,
    status varchar(32) NOT NULL CHECK (status IN ('COMPLETE','DISABLED','UNAUTHORIZED','UNSUPPORTED_API','PARTIAL','ERROR','STALE')),
    detail text,
    UNIQUE (tenant_id, run_id, provider, capability_id, account_id, region)
);
CREATE INDEX IF NOT EXISTS idx_ai_grid_capability_observations_run ON ai_grid_capability_observations (run_id, provider, capability_id);
ALTER TABLE ai_grid_capability_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_grid_capability_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_grid_capability_observations;
CREATE POLICY tenant_isolation ON ai_grid_capability_observations
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);


-- source: V67__converge_platform_line_schema_objects.sql
-- Converge tenant schemas with the tenant_default template for three objects that
-- were only ever created/shaped by the PLATFORM migration line (postgres_reset) and
-- therefore never reproduced by the tenant line:
--
--   1. demo_requests.uk_demo_requests_active_email  -- platform V46 (template only)
--   2. ingestion_jobs.uk_ingestion_jobs_dedupe_active -- platform V16 (different expr text)
--   3. demo_invites RLS policy tenant_isolation       -- template carries a permissive
--        variant; real tenants carry the strict V42 form
--
-- The control plane applies this migration to the tenant_default template first and
-- then to every tenant, so recreating each object with identical DDL on both sides
-- makes the structural fingerprint converge. This unblocks the fingerprint check in
-- ProductionBootstrapCli.migrateAndMark (which otherwise never marks a tenant CURRENT).
--
-- No behavior change for real tenants: they already carry the strict demo_invites
-- policy; only the template is normalised down to the strict form (never the reverse,
-- which would reintroduce the empty-context cross-tenant read the template variant allows).
--
-- ${tenantId}/${tenantSchema} are validated values supplied by the control plane.
DO $v67$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    tenant_id_nullable boolean;
    predicate text;
BEGIN
    IF current_schema() <> target_schema THEN
        RAISE EXCEPTION 'Tenant migration search_path mismatch: expected %, got %', target_schema, current_schema();
    END IF;

    -- 1) demo_requests: supersede duplicate active rows, then (re)create the partial
    --    unique index with canonical DDL (mirrors platform V46 exactly).
    UPDATE demo_requests request
       SET status = 'SUPERSEDED',
           rejection_reason = coalesce(request.rejection_reason, 'Superseded by a newer active request')
      FROM (
        SELECT id,
               row_number() OVER (PARTITION BY lower(email) ORDER BY requested_at DESC, id DESC) AS request_rank
          FROM demo_requests
         WHERE status IN ('PENDING', 'SENT', 'ERROR')
      ) ranked
     WHERE request.id = ranked.id
       AND ranked.request_rank > 1;

    DROP INDEX IF EXISTS uk_demo_requests_active_email;
    CREATE UNIQUE INDEX uk_demo_requests_active_email
        ON demo_requests (lower(email))
        WHERE status IN ('PENDING', 'SENT', 'ERROR');

    -- 2) ingestion_jobs: recreate the dedupe index with canonical DDL (mirrors platform
    --    V16 exactly) so the stored predicate text matches on both template and tenants.
    DROP INDEX IF EXISTS uk_ingestion_jobs_dedupe_active;
    CREATE UNIQUE INDEX uk_ingestion_jobs_dedupe_active
        ON ingestion_jobs (dedupe_key)
        WHERE status IN ('QUEUED', 'RUNNING');

    -- 3) demo_invites: normalise the RLS policy to the strict per-tenant form produced by
    --    tenant/V42__enforce_tenant_rls.sql. The predicate is generated with the same
    --    format() expression V42 uses, so the resulting policy text is byte-identical to
    --    what real tenants already have (no-op there) and the template converges to it.
    SELECT is_nullable = 'YES'
      INTO tenant_id_nullable
      FROM information_schema.columns
     WHERE table_schema = target_schema
       AND table_name = 'demo_invites'
       AND column_name = 'tenant_id';

    predicate := format(
        'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid',
        target_tenant::text
    );
    IF NOT tenant_id_nullable THEN
        predicate := predicate ||
            ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid';
    END IF;

    EXECUTE format('ALTER TABLE %I.demo_invites ENABLE ROW LEVEL SECURITY', target_schema);
    EXECUTE format('ALTER TABLE %I.demo_invites FORCE ROW LEVEL SECURITY', target_schema);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.demo_invites', target_schema);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I.demo_invites USING (%s) WITH CHECK (%s)',
                   target_schema, predicate, predicate);
END
$v67$;


-- source: V68__repair_demo_request_active_email_parity.sql
WITH ranked_active_requests AS (
    SELECT id,
           row_number() OVER (PARTITION BY lower(email) ORDER BY requested_at DESC, id DESC) AS request_rank
    FROM demo_requests
    WHERE status IN ('PENDING', 'SENT', 'ERROR')
)
UPDATE demo_requests request
SET status = 'SUPERSEDED',
    rejection_reason = coalesce(request.rejection_reason, 'Superseded by a newer active request')
FROM ranked_active_requests ranked
WHERE request.id = ranked.id
  AND ranked.request_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uk_demo_requests_active_email
    ON demo_requests (lower(email))
    WHERE status IN ('PENDING', 'SENT', 'ERROR');

