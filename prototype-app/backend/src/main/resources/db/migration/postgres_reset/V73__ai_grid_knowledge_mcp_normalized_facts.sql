-- migration-guard: platform-only
-- Provider-observed facts used by inventory and preview policy evaluation. Absence remains UNKNOWN.
INSERT INTO platform.ai_grid_fact_definitions
    (fact_key, version, value_type, claim_semantics, allowed_evidence_classes_json, allowed_workflow_uses_json, default_max_age_seconds)
VALUES
    ('data.source_type','1.0.0','STRING','Provider-reported AI data-source type.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_acl_enforced','1.0.0','BOOLEAN','Provider-reported data-source ACL enforcement state.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_public_content_access','1.0.0','BOOLEAN','Provider-reported public content-access state for an AI data source or store.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.source_sensitivity','1.0.0','STRING','Authoritative sensitivity state; missing or failed classification remains UNKNOWN.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.sensitivity_source','1.0.0','STRING','Authoritative sensitivity-classification provider.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('data.retrieval_mode','1.0.0','STRING','Provider-reported retrieval mode.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.inbound_auth_type','1.0.0','STRING','Provider-reported inbound gateway authorization type.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.outbound_auth_type','1.0.0','STRING','Provider-reported target credential-provider type without credentials.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.private_endpoint','1.0.0','BOOLEAN','Provider-reported private endpoint presence for MCP configuration.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400),
    ('mcp.last_synchronized_at','1.0.0','STRING','Provider-reported last successful MCP target synchronization time.','["CONFIGURATION"]','["POSTURE_FINDING"]',86400)
ON CONFLICT DO NOTHING;
