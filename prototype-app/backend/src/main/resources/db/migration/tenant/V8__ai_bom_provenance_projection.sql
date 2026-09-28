-- migration-guard: tenant-only
--
-- Storage for the provenance.ai_bom_present fact (registered in the platform fact catalog,
-- postgres_reset/V5__ai_bom_provenance_fact.sql) and the durable receipts that make projecting
-- it idempotent.
--
-- Deliberately not ai_grid_facts. Every row in that table requires a non-null artifact_id,
-- snapshot_manifest_id and run_id -- all tied to the connector snapshot/assessment pipeline. An
-- asset with an AI-BOM but no cloud connector has none of those, which is exactly the customer
-- this fact exists for. Its own evidence class (BOM_DOCUMENT, not CONFIGURATION) already marks
-- it as a different kind of fact; this gives it a storage shape that matches.

CREATE TABLE ${tenantSchema}.ai_bom_provenance_facts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    asset_id uuid NOT NULL REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    source_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_sources(id) ON DELETE CASCADE,
    -- The document version that produced this projection, so the claim traces to its evidence.
    bom_id uuid NOT NULL,

    fact_key varchar(255) NOT NULL DEFAULT 'provenance.ai_bom_present',
    value_boolean boolean NOT NULL DEFAULT true,
    -- Matches the platform fact definition's allowed_evidence_classes_json. A document
    -- assertion must never be conflated with provider-observed configuration.
    evidence_class varchar(32) NOT NULL DEFAULT 'BOM_DOCUMENT',

    -- Allowlisted document metadata only -- bounded, non-sensitive fields, nothing else.
    bom_format varchar(32),
    spec_version varchar(32),

    -- Kept separate on purpose: when the document was ingested is not when this row was last
    -- (re)projected, and conflating them would misreport staleness.
    document_ingested_at timestamptz NOT NULL,
    projected_at timestamptz NOT NULL DEFAULT now(),
    projection_version integer NOT NULL DEFAULT 1,

    -- One current row per asset per fact key. A later projection updates it in place, the same
    -- way bom_sources.current_bom_id tracks current state rather than piling up history.
    UNIQUE (tenant_id, asset_id, fact_key),

    CONSTRAINT ai_bom_provenance_facts_evidence_class_check
        CHECK (evidence_class = 'BOM_DOCUMENT')
);

CREATE INDEX idx_ai_bom_provenance_facts_source
    ON ${tenantSchema}.ai_bom_provenance_facts(tenant_id, source_id);

ALTER TABLE ${tenantSchema}.ai_bom_provenance_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_provenance_facts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_provenance_facts
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Durable completed-work receipts. A redelivered or re-claimed job must never project twice --
-- the job's own QUEUED/RUNNING dedupe only prevents duplicate *queued* work, not a retry after
-- the real work already finished.
CREATE TABLE ${tenantSchema}.ai_bom_projection_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    source_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_sources(id) ON DELETE CASCADE,
    -- Keyed by the source's revision at the time this receipt was written, so obsolete work
    -- (an older revision than the source's current one) is never mistaken for up to date.
    source_revision bigint NOT NULL,
    operation varchar(64) NOT NULL,
    projection_version integer NOT NULL DEFAULT 1,
    completed_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, source_id, source_revision, operation, projection_version)
);

ALTER TABLE ${tenantSchema}.ai_bom_projection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_bom_projection_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_bom_projection_receipts
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
