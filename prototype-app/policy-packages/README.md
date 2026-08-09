# AI policy packages

Policy definitions are reviewed as versioned JSON packages and imported through the platform-only `POST /api/platform/ai-grid/policies/imports` endpoint. A package is never edited after import: create a new semantic version instead.

Required fields mirror the governed catalog: identity, severity/workflow, applicability, evidence contract, bounded predicate, remediation, framework mappings, and a Git source reference. High and Critical packages additionally require answer-key and precision-review evidence before publication.

CI performs structural validation. Platform import performs authoritative fact-registry and predicate validation; publication performs answer-key, independent-approval, and precision gates.
