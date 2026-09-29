-- migration-guard: platform-only
--
-- Registers the fact that an AI-BOM was ingested for an asset.
--
-- Two deliberate choices encoded here.
--
-- The evidence class is BOM_DOCUMENT, not CONFIGURATION. Every existing provenance fact is
-- derived from a provider's live configuration; this one comes from a document a customer
-- uploaded. Conflating them would let a document assertion satisfy a policy that means to
-- require provider-observed configuration.
--
-- The allowed workflow use is COVERAGE_CONTEXT and deliberately not POSTURE_FINDING. This
-- fact records that a document exists, which is not a posture claim: an AI-BOM is partial by
-- nature and says nothing about whether model coverage is complete. Allowing it as a finding
-- input would enable exactly the BOM coverage policies that are meant to stay disabled.

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds, lifecycle)
VALUES
    ('provenance.ai_bom_present', '1.0.0', 'BOOLEAN',
     'An AI-BOM document was ingested for the asset. Records document presence only: it does not assert that the document is complete, nor that model coverage is complete.',
     '["BOM_DOCUMENT"]'::jsonb,
     '["COVERAGE_CONTEXT"]'::jsonb,
     NULL,
     'ACTIVE')
ON CONFLICT (fact_key, version) DO UPDATE SET
    value_type = excluded.value_type,
    claim_semantics = excluded.claim_semantics,
    allowed_evidence_classes_json = excluded.allowed_evidence_classes_json,
    allowed_workflow_uses_json = excluded.allowed_workflow_uses_json,
    default_max_age_seconds = excluded.default_max_age_seconds,
    lifecycle = excluded.lifecycle;
