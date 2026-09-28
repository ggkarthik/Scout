-- migration-guard: tenant-only
--
-- Milestone 1 of AI-BOM integration: a common BOM document lifecycle.
--
-- Before this migration a BOM document's identity WAS its replacement key: the ingestion
-- path looked up the current record by (tenant_id, bom_type, asset_id, lower(supplier))
-- and superseded whatever it found. That made "replace this source" indistinguishable from
-- "here is an unrelated document that happens to share a supplier", and there was no stored
-- link at all between a bom_components row and the inventory_components row it justified --
-- the match was recomputed at ingest time and discarded.
--
-- This introduces stable logical sources (bom_sources) holding immutable document versions
-- with one current pointer, plus a many-to-many contribution mapping so a component can be
-- supported by several sources independently. Reconciliation can then withdraw one source's
-- support without inferring that the component is gone.

CREATE TABLE ${tenantSchema}.bom_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    bom_type varchar(20) NOT NULL,
    asset_id uuid REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    supplier varchar(255),
    source_reference text,
    -- Deterministic identity for automated callers (a GitHub repo, a GHCR image, a remote
    -- endpoint) so each scheduled run replaces its own source instead of creating another.
    -- Null for manual uploads, where omitting a source id deliberately creates an
    -- independent source rather than implicitly replacing anything.
    source_key varchar(700),
    -- Immutable version chain lives on bom_ingestion_records.source_id; this points at the
    -- one that is current. Deliberately independent of document id and checksum.
    current_bom_id uuid,
    -- Monotonic per source. Milestone 2 keys projection work by (source_id, revision) so
    -- obsolete work can be discarded rather than reprocessed.
    revision bigint NOT NULL DEFAULT 0,
    completeness varchar(32) NOT NULL DEFAULT 'PARTIAL',
    state varchar(32) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT bom_sources_completeness_check
        CHECK (completeness IN ('PARTIAL', 'COMPLETE_ASSET_SOFTWARE')),
    CONSTRAINT bom_sources_state_check
        CHECK (state IN ('ACTIVE', 'HELD_ENTITLEMENT', 'DEFERRED')),
    -- A CBOM describes cryptographic assets, never the asset's full software inventory,
    -- so it can never assert software completeness.
    CONSTRAINT bom_sources_cbom_not_software_complete_check
        CHECK (NOT (bom_type = 'CBOM' AND completeness = 'COMPLETE_ASSET_SOFTWARE'))
);

-- Completeness is an audited claim, not a flag: asserting COMPLETE_ASSET_SOFTWARE lets a
-- later replacement record authoritative absence, which is the only path that may retire a
-- component. Every replacement must repeat the assertion, so this is append-only history.
CREATE TABLE ${tenantSchema}.bom_source_completeness_assertions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    source_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_sources(id) ON DELETE CASCADE,
    bom_id uuid NOT NULL,
    completeness varchar(32) NOT NULL,
    asset_scope_json jsonb NOT NULL,
    asserted_by varchar(255) NOT NULL,
    asserted_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT bom_source_assertion_completeness_check
        CHECK (completeness IN ('PARTIAL', 'COMPLETE_ASSET_SOFTWARE')),
    CONSTRAINT bom_source_assertion_scope_check
        CHECK (jsonb_typeof(asset_scope_json) = 'object')
);

-- The mapping that did not exist. One row per (source, inventory component): the source's
-- standing claim that the component is present. Withdrawing a claim is not the same as the
-- component being absent -- absence requires authoritative_absence under an asserted
-- COMPLETE_ASSET_SOFTWARE scope.
CREATE TABLE ${tenantSchema}.bom_component_contributions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    source_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_sources(id) ON DELETE CASCADE,
    -- Document version that last carried this claim.
    bom_id uuid NOT NULL,
    -- Nullable: backfilled legacy rows reconstruct the inventory link from the shared
    -- sbom_upload_id and may not identify which bom_components row justified it.
    bom_component_id uuid,
    inventory_component_id uuid NOT NULL
        REFERENCES ${tenantSchema}.inventory_components(id) ON DELETE CASCADE,
    resolved_identity_key varchar(700) NOT NULL,
    contribution_state varchar(24) NOT NULL DEFAULT 'SUPPORTED',
    authoritative_absence boolean NOT NULL DEFAULT false,
    first_contributed_at timestamptz NOT NULL DEFAULT now(),
    last_contributed_at timestamptz NOT NULL DEFAULT now(),
    withdrawn_at timestamptz,
    UNIQUE (tenant_id, source_id, inventory_component_id),
    CONSTRAINT bom_contribution_state_check
        CHECK (contribution_state IN ('SUPPORTED', 'WITHDRAWN')),
    -- withdrawn_at is the withdrawal audit timestamp and must agree with the state.
    CONSTRAINT bom_contribution_withdrawal_timestamp_check
        CHECK ((contribution_state = 'WITHDRAWN') = (withdrawn_at IS NOT NULL)),
    -- Authoritative absence is a withdrawal outcome, never a standing supported claim.
    CONSTRAINT bom_contribution_absence_requires_withdrawal_check
        CHECK (NOT (authoritative_absence AND contribution_state = 'SUPPORTED'))
);

-- Reconciliation gate. New withdrawal/retirement rules are only safe for an asset whose
-- historical contribution rows have been reconstructed; until then the asset's components
-- are LEGACY_UNKNOWN and no absence may be inferred. Ships with the migration so the guard
-- can never lag the schema it protects.
CREATE TABLE ${tenantSchema}.bom_asset_backfill_state (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    asset_id uuid NOT NULL REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    state varchar(24) NOT NULL DEFAULT 'PENDING',
    attempt_count integer NOT NULL DEFAULT 0,
    backfilled_at timestamptz,
    failure_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, asset_id),
    CONSTRAINT bom_asset_backfill_state_check
        CHECK (state IN ('PENDING', 'BACKFILLED', 'FAILED')),
    CONSTRAINT bom_asset_backfill_completion_check
        CHECK ((state = 'BACKFILLED') = (backfilled_at IS NOT NULL))
);

-- The three CHECKs below are NOT VALID on purpose: they enforce every new and updated row,
-- but skip validating pre-existing ones, which would scan these (potentially very large)
-- tables under ACCESS EXCLUSIVE. Existing rows already satisfy them via the column defaults.
ALTER TABLE ${tenantSchema}.bom_ingestion_records
    ADD COLUMN source_id uuid REFERENCES ${tenantSchema}.bom_sources(id);
ALTER TABLE ${tenantSchema}.bom_ingestion_records
    ADD COLUMN completeness varchar(32) NOT NULL DEFAULT 'PARTIAL';
ALTER TABLE ${tenantSchema}.bom_ingestion_records
    ADD CONSTRAINT bom_ingestion_records_completeness_check
        CHECK (completeness IN ('PARTIAL', 'COMPLETE_ASSET_SOFTWARE')) NOT VALID;

-- Aggregate evidence state, kept separate from component_status (ACTIVE/RETIRED) on purpose:
-- status is presence, this is what the evidence says about presence. Every pre-existing row
-- starts LEGACY_UNKNOWN, so from the instant this migration lands a missing contribution row
-- can never be read as absence.
ALTER TABLE ${tenantSchema}.inventory_components
    ADD COLUMN bom_evidence_state varchar(24) NOT NULL DEFAULT 'LEGACY_UNKNOWN';
ALTER TABLE ${tenantSchema}.inventory_components
    ADD COLUMN bom_evidence_updated_at timestamptz;
ALTER TABLE ${tenantSchema}.inventory_components
    ADD CONSTRAINT inventory_components_bom_evidence_state_check
        CHECK (bom_evidence_state IN
            ('SUPPORTED', 'CONFLICTING', 'WITHDRAWN', 'LEGACY_UNKNOWN')) NOT VALID;

-- CBOM keeps its own evaluator and findings store; it gains only the evidence lifecycle.
-- Withdrawal must preserve status and resolved_at -- subsequent evaluation decides
-- resolution -- so neither column is touched here.
ALTER TABLE ${tenantSchema}.cbom_risk_findings
    ADD COLUMN evidence_state varchar(24) NOT NULL DEFAULT 'SUPPORTED';
ALTER TABLE ${tenantSchema}.cbom_risk_findings
    ADD COLUMN withdrawn_at timestamptz;
ALTER TABLE ${tenantSchema}.cbom_risk_findings
    ADD CONSTRAINT cbom_risk_findings_evidence_state_check
        CHECK (evidence_state IN
            ('SUPPORTED', 'CONFLICTING', 'WITHDRAWN', 'LEGACY_UNKNOWN')) NOT VALID;

CREATE INDEX idx_bom_sources_tenant_asset
    ON ${tenantSchema}.bom_sources(tenant_id, asset_id, bom_type);
CREATE INDEX idx_bom_sources_tenant_state
    ON ${tenantSchema}.bom_sources(tenant_id, state);
-- Partial: only keyed sources are unique. Manual uploads leave source_key null and any
-- number of them may coexist for the same asset.
CREATE UNIQUE INDEX uk_bom_sources_tenant_source_key
    ON ${tenantSchema}.bom_sources(tenant_id, source_key) WHERE source_key IS NOT NULL;
CREATE INDEX idx_bom_source_assertions_source
    ON ${tenantSchema}.bom_source_completeness_assertions(tenant_id, source_id, asserted_at DESC);
CREATE INDEX idx_bom_contributions_inventory
    ON ${tenantSchema}.bom_component_contributions(tenant_id, inventory_component_id, contribution_state);
CREATE INDEX idx_bom_contributions_source
    ON ${tenantSchema}.bom_component_contributions(tenant_id, source_id, contribution_state);
CREATE INDEX idx_bom_contributions_bom
    ON ${tenantSchema}.bom_component_contributions(bom_id);
CREATE INDEX idx_bom_asset_backfill_pending
    ON ${tenantSchema}.bom_asset_backfill_state(tenant_id, state);
CREATE INDEX idx_bom_ingestion_records_source
    ON ${tenantSchema}.bom_ingestion_records(source_id);
CREATE INDEX idx_inventory_components_bom_evidence
    ON ${tenantSchema}.inventory_components(tenant_id, bom_evidence_state);

ALTER TABLE ${tenantSchema}.bom_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_sources
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.bom_source_completeness_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_source_completeness_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_source_completeness_assertions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.bom_component_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_component_contributions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_component_contributions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.bom_asset_backfill_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_asset_backfill_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_asset_backfill_state
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
