# AI Security Pilot Readiness

AI Security is a stacked delivery on top of the Phase 0 entitlement correction. Code completion
does not authorize tenant enablement. Record evidence for every gate below before changing the
`ai.security` entitlement.

## Pull Request Order

1. Merge and deploy the Phase 0 entitlement PR independently.
2. Run the entitlement resolver in `SHADOW` for at least seven consecutive days.
3. Explain all mismatches, then enable `ENFORCE` for the internal-tenant canary only.
4. Merge the AI Security pilot PR after Phase 0 canary verification.
5. Keep the AI Security job kill switch off until migrations and connector permissions pass in
   staging.

The AI Security PR may be reviewed as a stacked PR before Phase 0 merges, but it must not be
released with Phase 0 as one combined production change.

## Staging Gates

| Gate | Required evidence |
| --- | --- |
| Migration rehearsal | Platform V48 and tenant V45 applied to a production-like template, canary tenant, and batch; fingerprints and rollback notes captured |
| Isolation | Forced-RLS tests, cross-tenant API/job/observation attempts, and platform-without-tenant-context checks pass |
| CVE/SBOM regression | Correlation output, queue depth, latency, retries, restart recovery, and finding counts remain within the approved baseline |
| Secret remediation | Production bundle scan passes and any previously browser-exposed provider key is rotated |
| AWS connector | Workload identity or cross-account role succeeds without static keys; missing permissions produce sanitized diagnostics |
| Operations | AI executor, queue wait, tenant fairness, throttling, scope completeness, kill switch, and coverage alerts are visible |

## AWS Certification

Use representative internal AWS accounts covering:

- Empty Bedrock account and unsupported regions.
- Agents with and without models, action groups, knowledge bases, guardrails, and execution roles.
- Complete, partial, denied, throttled, and timed-out discovery scopes.
- Regional resources that depend on account-global IAM evidence.
- Public and private S3 sources, authenticated and unauthenticated Lambda URLs, wildcard and
  least-privilege IAM policies, weak and sufficient guardrails, and enabled/disabled invocation
  logging.

Inventory precision must be at least 95% per resource family. Investigate every missed in-scope
artifact; do not average misses together with harmless over-reporting.

## Policy Quality Gate

The Policies page is the pilot gate of record. It displays evaluated sample size, `NO_DECISION`
count, required threshold, and a pass/block status.

- Critical policies require 100% decision coverage.
- High and Medium policies require at least 95% decision coverage.
- Precision must be at least 95% per policy and resource family, with sample size recorded.
- Every unexplained `NO_DECISION` and under-reported artifact must be investigated.
- `NOT_APPLICABLE` evaluations are excluded from decision coverage.

Do not enable the design partner while any policy displays `NO_DATA` or a blocked coverage gate.

## Internal Soak

After all staging and internal-tenant gates pass, run findings for seven consecutive stable days.
Hand-validate evidence and review false positives throughout the window.

Restart the soak after any change to:

- Policy logic or version.
- Required-scope declarations.
- Discovery normalization.
- Evidence rendering.

Design-partner enablement is a separate approval after the soak. Roll back immediately by disabling
the `ai.security` tenant override or the AI Security job kill switch if tenant isolation, CVE/SBOM
regression, unsafe findings, or sustained queue/SLO degradation is observed.
