-- migration-guard: platform-only
INSERT INTO platform.ai_grid_technology_versions
    (technology_id, version, display_name, provider, lifecycle, resource_families_json)
VALUES
    ('AZURE_AI_SERVICES', '1.1.0', 'Azure AI Services', 'AZURE', 'ACTIVE',
     '["AZURE_AI_ACCOUNTS","AZURE_DIAGNOSTIC_SETTINGS","AZURE_RAI_POLICIES"]')
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json,
     allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('guardrail.rai_non_blocking_filter_observed','1.0.0','BOOLEAN',
     'Every returned RAI content-filter entry had explicit enabled and blocking booleans; true means at least one entry was disabled or non-blocking.',
     '["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('guardrail.rai_policy_reference_configured','1.0.0','STRING',
     'Provider configuration names the RAI policy associated with an Azure model deployment.',
     '["CONFIGURATION"]','["POSTURE_FINDING","EXPOSURE_HYPOTHESIS"]',86400)
ON CONFLICT DO NOTHING;

INSERT INTO platform.ai_grid_policy_versions (
    policy_id, version, name, description, severity, lifecycle, workflow_class, default_selection,
    artifact_types_json, native_kinds_json, required_resource_families_json, required_facts_json,
    predicate_json, reason_code, remediation, framework_mappings_json, scope_resolution,
    approved_by, approved_at, published_at
) VALUES (
    'AZURE_RAI_POLICY_NON_BLOCKING_FILTER','1.0.0','Azure RAI policy contains a non-blocking filter',
    'An Azure RAI policy explicitly disables a returned content filter or configures it as non-blocking.',
    'HIGH','PUBLISHED','POSTURE_FINDING','ENABLED','["AI_GUARDRAIL"]','["AZURE_RAI_POLICIES"]',
    '["AZURE_RAI_POLICIES"]',
    '[{"factKey":"guardrail.rai_non_blocking_filter_observed","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
    '{"fact":"guardrail.rai_non_blocking_filter_observed","eq":true}',
    'AZURE_RAI_FILTER_DISABLED_OR_NON_BLOCKING',
    'Enable blocking for every explicitly configured RAI content filter. Review category and threshold completeness separately.',
    '{"OWASP_LLM_TOP_10":["LLM01","LLM09"]}','STATIC','ai-grid-r1-azure-rai-slice',now(),now()
) ON CONFLICT DO NOTHING;
