# AI policy packages

Policy definitions are reviewed as versioned JSON packages and imported through the platform-only `POST /api/platform/ai-grid/policies/imports` endpoint. A package is never edited after import: create a new semantic version instead.

Required fields mirror the governed catalog: identity, severity/workflow, applicability, evidence contract, bounded predicate, remediation, framework mappings, and a Git source reference. High and Critical packages additionally require answer-key and precision-review evidence before publication.

CI performs structural validation. Platform import performs authoritative fact-registry and predicate validation; publication performs answer-key, independent-approval, and precision gates.

## Evidence-certification wave

`agcf/phase-2-catalog-contract.json` declares the small, evidence-backed Phase 2 certification wave: AWS effective permissions 039–042, Azure effective access 033–039, AWS vector retrieval 048–050, and AgentCore inbound/outbound authentication 071–072. Their OWASP mappings are `DIRECT` because the normalized evidence evaluates the mapped risk directly; this does **not** count as effective tenant coverage or unpause them.

Each still ships `PAUSED`/`DISABLED`. It may move only through the validation-governance flow: answer-key evidence, passing precision review, independent mapping review, approval, and a canary rollout before general availability.
