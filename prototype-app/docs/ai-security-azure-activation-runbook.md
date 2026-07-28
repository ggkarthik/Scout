# Azure AI Security activation runbook

## Engineering state

The Azure provider is implemented inside the tenant-scoped AI Security module.
AWS, SBOM, Asset, vulnerability, and CVE correlation paths remain separate.
Search data-plane discovery and workload federation stay disabled until their
ADRs pass live security validation.

## Required preflight

1. Deploy tenant migration V46 and platform migration V49 and confirm schema
   parity, tenant creation, reset, and deletion tests.
2. Enable `ai.security` only for the internal tenant.
3. Set `APP_AI_SECURITY_AZURE_ENABLED=true`.
4. Create a dedicated client-secret profile, verify its expiry, bind an
   existing Azure target, and run the generated permission test.
5. Confirm no prohibited Search/key/document actions are present in the role.
6. Capture AWS AI, Azure Asset, SBOM, ingestion recovery, and CVE correlation
   baselines before enabling the first Azure slice.

## Slice activation

Activate exactly one slice at a time by limiting the connector resource-family
selection:

1. Foundry accounts, projects, deployments, diagnostics, and global RBAC.
2. Foundry agents and tools, with the preview adapter flag enabled.
3. Azure ML workspaces, models, endpoints, deployments, compute, jobs, and
   pipelines.
4. Azure AI Search control plane.
5. Azure AI Search data plane only after the Search ADR is approved.
6. Azure Bot Service registrations, channels, and identities.

Each slice requires seven stable days. Any normalization, policy logic,
required-scope, evidence rendering, or provider API change resets that slice.
Do not activate the next slice until inventory misses, unexplained
`NO_DECISION` results, and incomplete scopes are resolved or formally accepted.

## Emergency controls

- Provider: `APP_AI_SECURITY_AZURE_ENABLED=false`
- Tenants: `APP_AI_SECURITY_AZURE_DISABLED_TENANT_IDS`
- Connectors: `APP_AI_SECURITY_AZURE_DISABLED_CONNECTOR_IDS`
- Families: `APP_AI_SECURITY_AZURE_DISABLED_RESOURCE_FAMILIES`
- Policies: `APP_AI_SECURITY_AZURE_DISABLED_POLICY_IDS`
- Preview agents: `APP_AI_SECURITY_AZURE_FOUNDRY_AGENTS_ENABLED=false`
- Search data plane: `APP_AI_SECURITY_AZURE_SEARCH_DATA_PLANE_ENABLED=false`

Family disablement produces non-authoritative `UNSUPPORTED` scopes. Policy
disablement suppresses open findings rather than resolving them. Credential
emergency revoke prevents new discovery jobs from resolving the profile.

## Acceptance

- Inventory precision is at least 95% for every enabled family and every miss
  is root-caused.
- Critical decision coverage is 100%; High and Medium are at least 95%.
- Policy precision is at least 95% with sample size recorded.
- Cross-tenant IDs, jobs, targets, connectors, credentials, observations,
  graphs, findings, and policy counts are rejected.
- No credentials, provider payloads, Search keys, documents, prompts, or
  instructions appear in durable jobs, evidence, logs, telemetry, or bundles.
- Existing AWS AI, Azure Asset, SBOM, and CVE baselines remain equivalent.

External enablement requires a separate approval after all enabled internal
slices pass their soak. Soak time is an activation gate and cannot be replaced
by automated tests.
