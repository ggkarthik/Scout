-- migration-guard: platform-only
-- Seeds connector-capability backlog candidates for the detectors retired in the Phase 1
-- catalog migration (V80) for insufficient evidence. Each carries machine-readable
-- reactivation criteria so the deprecation is tracked, not silently dropped. Idempotent:
-- fixed ids + ON CONFLICT DO NOTHING.
INSERT INTO platform.ai_grid_policy_candidates
    (id, title, source_type, status, technology_id, rationale,
     risk_score, reach_score, evidence_maturity, remediation_clarity, owner, created_by)
VALUES
('5523bc91-acd7-43c0-bfb3-b357726d65b3',
 'Public MCP endpoint reachable without configured authentication',
 'CONNECTOR_CAPABILITY', 'COLLECTOR_BACKLOG', 'AWS_BEDROCK_AGENTCORE',
 'Retired from Phase 1 (POLICY_RETIRED_INSUFFICIENT_EVIDENCE): collectors persist EXTERNAL_ENDPOINT but not authoritative PUBLIC_NETWORK_REACHABLE. Reactivation criteria: add consented, non-invasive reachability verification or provider network-policy metadata that authoritatively proves public reachability. Never infer reachability from a URL.',
 3, 2, 1, 2, 'ai-grid-phase-1', 'ai-grid-phase-1'),
('b8320126-7259-43eb-a6ee-5ebb714e52a9',
 'Azure AI Search data-source non-identity authentication',
 'CONNECTOR_CAPABILITY', 'COLLECTOR_BACKLOG', 'AZURE_AI_SEARCH',
 'Retired from Phase 1 (POLICY_RETIRED_INSUFFICIENT_EVIDENCE): connection strings are intentionally not persisted, so non-identity authentication cannot be proven. Reactivation criteria: implement a secret-safe Search data-plane auth classifier that persists only MANAGED_IDENTITY | KEY_OR_SAS | UNKNOWN, never secret material.',
 3, 2, 1, 2, 'ai-grid-phase-1', 'ai-grid-phase-1')
ON CONFLICT (id) DO NOTHING;
