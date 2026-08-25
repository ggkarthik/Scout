-- migration-guard: platform-only
-- Seeds the governed next-target connector-capability backlog from the Phase 1 plan's
-- enhancement categories. These are forward-looking candidates (RESEARCH), not shipped
-- coverage, so the backlog is funded and bounded rather than implicit. Idempotent:
-- fixed ids + ON CONFLICT DO NOTHING. Evidence-maturity is deliberately low (evidence
-- is not yet collectable); risk/reach reflect plan priority ordering.
INSERT INTO platform.ai_grid_policy_candidates
    (id, title, source_type, status, technology_id, rationale,
     risk_score, reach_score, evidence_maturity, remediation_clarity, owner, created_by)
VALUES
('893b8993-6316-466e-bf2e-0b3501d3e753',
 'Effective AWS IAM and Azure RBAC decisions',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #1: resolve effective permissions (IAM SimulatePrincipalPolicy / Access Analyzer; Azure role definitions, deny assignments, PIM) to decide excessive-agency posture. Store decisions, not raw sensitive policy bodies.',
 5, 5, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('63d5c39a-2ae9-43e9-af9f-8cad83af5fba',
 'Referenced backing-store network, encryption, and authentication metadata',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #2: enrich directly referenced S3 / Azure Storage / Search / vector-store resources with public-access-block, encryption (CMK), TLS, and private-endpoint metadata. Preserve account-level ambiguity as NO_DECISION.',
 5, 4, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('9844ab16-eef2-47e7-8555-4e10e362e93b',
 'Secret-safe Search/MCP auth classification, ACL, retrieval mode, private endpoint',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #3: classify Search/MCP authentication in memory (MANAGED_IDENTITY | KEY_OR_SAS | UNKNOWN), extract ACL/permission-filter and retrieval-mode metadata, and emit authoritative private-endpoint state. Never persist secrets or connection strings.',
 4, 4, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('e5642902-fd08-4029-952f-edba68de8bcf',
 'Bedrock and Azure consumption, quota, budget, and alarm telemetry',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #4: add CloudWatch / Azure Monitor invocation, token, throttle and quota-usage metrics plus Budgets / Cost Management and alarm inventory to decide unbounded-consumption posture. Prefer counters over prompt/output bodies.',
 3, 4, 1, 3, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('147bc58c-be61-4803-b7af-eac27771eec6',
 'Model/data provenance, signatures, registry lineage, SBOM/AI-BOM, and vulnerabilities',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #5: add model-registry / ECR / ACR attestation, MLflow lineage, checksums/signatures, and SBOM/AI-BOM + vulnerability evidence for supply-chain and data-poisoning coverage (AICM MDS/STA). Resolve only referenced artifacts; never read object content.',
 4, 3, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1'),
('d3ba37fa-e266-4b87-af36-49e4948a5fbc',
 'Opt-in runtime prompt-injection, content-safety, output-handling, and reachability evidence',
 'CONNECTOR_CAPABILITY', 'RESEARCH', NULL,
 'Next-target #6: behind explicit consent, add runtime guardrail/content-safety verdicts, evaluation results, and non-invasive reachability verification for LLM01/07/08/10 runtime signals. Store test ids, scores, and hashes rather than prompt/output bodies; never infer public reachability from a URL.',
 3, 3, 1, 2, 'ai-grid-phase-2', 'ai-grid-phase-1')
ON CONFLICT (id) DO NOTHING;
