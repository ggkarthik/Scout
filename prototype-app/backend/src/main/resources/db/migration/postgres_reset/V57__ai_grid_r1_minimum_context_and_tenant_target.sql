-- migration-guard: platform-only
-- Exact claim keys prevent baseline proxies from satisfying verified context requirements.

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('identity.effective_admin_access_derived','1.0.0','BOOLEAN',
     'Effective administrative access derived from an approved identity graph and authorization model.',
     '["GRAPH_ANALYSIS"]','["EXPOSURE_HYPOTHESIS","VALIDATED_EXPOSURE"]',3600),
    ('data.source_linked','1.0.0','BOOLEAN',
     'A provider or graph relationship links the AI artifact to a data source; this does not classify content.',
     '["RELATIONSHIP_GRAPH"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400),
    ('data.sensitive_content_confirmed','1.0.0','BOOLEAN',
     'An approved data-classification method confirmed sensitive content reachable from the AI system.',
     '["DATA_CLASSIFICATION","RUNTIME_OBSERVATION"]','["VALIDATED_EXPOSURE"]',3600),
    ('owner.confirmed','1.0.0','OBJECT',
     'An authorized user or approved service-catalog mapping confirmed the accountable owner.',
     '["USER_ASSERTION","SERVICE_CATALOG"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',null)
ON CONFLICT DO NOTHING;

ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 52;
UPDATE platform.tenant_schema_versions
SET target_version = 52,
    status = CASE WHEN current_version < 52 THEN 'PENDING' ELSE status END,
    updated_at = now()
WHERE target_version < 52;

