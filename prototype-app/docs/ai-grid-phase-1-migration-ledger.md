# AI Grid Phase 1 migration ledger

The former posture identifiers are reconciled to the Phase 1 objective IDs without deleting historic assessments, findings, reviews, or evidence. Tenant selection, scope, parameters, and compatible artifact overrides migrate with the lineage.

| Legacy policy | Disposition | Phase 1 target |
|---|---|---|
| `AWS_BEDROCK_WEAK_GUARDRAIL` | one-to-one replacement | `AGCF-AWS-002` |
| `AWS_BEDROCK_PUBLIC_KB_S3` | one-to-one replacement | `AGCF-AWS-017` |
| `AWS_BEDROCK_UNAUTH_LAMBDA_URL` | one-to-one replacement | `AGCF-AWS-006` |
| `AWS_BEDROCK_WILDCARD_AGENT_ROLE` | one-to-one replacement | `AGCF-AWS-005` |
| `AWS_BEDROCK_INVOCATION_LOGGING_DISABLED` | one-to-one replacement | `AGCF-AWS-009` |
| `AZURE_RAI_POLICY_NON_BLOCKING_FILTER` | one-to-one replacement | `AGCF-AZR-010` |
| `AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS` | one-to-one replacement | `AGCF-AZR-001` |
| `AZURE_AI_LOCAL_AUTH_ENABLED` | one-to-one replacement | `AGCF-AZR-003` |
| `AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED` | one-to-one replacement | `AGCF-AZR-005` |
| `AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED` | one-to-one replacement | `AGCF-AZR-017` |
| `AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED` | one-to-one replacement | `AGCF-AZR-022` |
| `AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED` | one-to-one replacement | `AGCF-AZR-026` |
| `AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY` | one-to-one replacement | `AGCF-AZR-027` |
| `MCP_TARGET_UNHEALTHY_OR_SYNC_UNSUCCESSFUL` | one-to-one replacement | `AGCF-AWS-033` |
| `SENSITIVE_AI_DATA_SOURCE_WITH_PUBLIC_CONTENT_ACCESS` | one-to-one replacement | `AGCF-AWS-024` |
| `BEDROCK_GUARDRAIL_NOT_ATTACHED` | one-to-one replacement | `AGCF-AWS-001` |
| `AZURE_BOT_MANAGED_IDENTITY_MISSING` | one-to-one replacement | `AGCF-AZR-028` |
| `AZURE_RBAC_BROAD_ASSIGNMENT` | one-to-one replacement | `AGCF-AZR-030` |
| `BEDROCK_AGENT_INACTIVE_OR_ROLE_MISSING` | split replacement | `AGCF-AWS-003`, `AGCF-AWS-004` |
| `MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH` | retired: insufficient reachability evidence | — |
| `AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH` | retired: no secret-safe auth classifier | — |

The catalog also introduces 50 Phase 1 posture adapters without a seeded predecessor. The existing three correlations are retained, three additional correlations are authored, and all six are represented by `AGCF-XSP-001` through `AGCF-XSP-006` governed envelopes.

| Legacy correlation | Disposition | Phase 1 envelope |
|---|---|---|
| `R2_EXTERNAL_SENSITIVE_ACCESS` | retained governed envelope | `AGCF-XSP-001` |
| `R2_EXCESSIVE_TOOL_PRIVILEGE` | retained governed envelope | `AGCF-XSP-003` |
| `R2_UNTRUSTED_AUTONOMOUS_EXECUTION` | retained governed envelope | `AGCF-XSP-002` |

Retired policies become unavailable and `RETIRED`; open findings and coverage gaps close with `POLICY_RETIRED_INSUFFICIENT_EVIDENCE`. Their historical detail remains available with a deprecation banner and a governed connector-capability candidate recording reactivation criteria.
