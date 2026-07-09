# Performance Final Stretch Checklist

## Delivery 1: Background-Work Isolation Completion
- Status: Complete
- Closure notes:
- Runtime-role gating now suppresses worker-grade schedulers and queue pollers on API-serving nodes when `APP_RUNTIME_ROLE=api`.
- Vulnerability ingestion, SBOM ingestion, projection maintenance, external sync sweeps, and incident-status sync all follow the worker-safe background-task policy path.
- Single-node environments intentionally keep the default `APP_RUNTIME_ROLE=all` behavior for compatibility; split API-versus-worker expectations are documented in the governance runbook.
- Goal: ensure background and orchestration work runs tenant-first and is worker-safe by default.
- Exit criteria:
- All remaining manual trigger and scheduler entrypoints follow the pattern "tenant selected first, transaction second".
- API-serving nodes suppress worker-grade scheduled and queue-polled background work by runtime role, while preserving existing manual trigger timing semantics.
- Remaining exceptions are explicitly documented with rationale.
- Focus areas:
- Connector sync triggers and scheduled jobs.
- Vulnerability ingestion trigger family and queued worker execution.
- Incident sync, ingestion orchestration, and any remaining worker-grade entrypoints on API paths.

## Delivery 2: Correlation Freshness And Projection SLO Closure
- Status: Complete
- Closure notes:
- `finding_delta_queue` drain remains bounded and stale/processing counters are green in `/api/slo/status`.
- Finding projection freshness is green in both `/api/slo/status` and `/api/operations/performance-scorecard`.
- Resource scorecard no longer false-fails when the single-thread integration queue executor is actively processing work without backlog.
- Goal: make queue age, projection freshness, and analyst-visible recompute lag reliably compliant.
- Exit criteria:
- `/api/slo/status` and the performance scorecard are green for correlation freshness and projection lag on seeded enterprise data.
- Queue backlog remains bounded under mixed read/write/background load.
- Finding projection refresh completes within the declared SLO envelope.
- Focus areas:
- `finding_delta_queue` drain stability.
- Finding projection refresh cadence and stuck-state recovery.
- Targeted recompute and metadata refresh completion time.

## Delivery 3: Enterprise Certification Run And Gap Report
- Status: Complete
- Closure notes:
- `performance-baseline.sh` now fails fast when route sampling only hits tenant/auth guardrails instead of returning real tenant-scoped data.
- `correlation-certification.sh` now distinguishes historical failed-event residue from fresh failed-event growth, so certification gates on current behavior instead of permanently stale counts.
- A full local-profile enterprise certification pass completed successfully with baseline, correlation, and final scorecard artifacts all green.
- Goal: replace inferred progress with one evidence-backed certification pass.
- Exit criteria:
- Baseline, correlation, and enterprise certification scripts run successfully against seeded scale data.
- Current-state versus target report is captured for route latency, freshness, and resource ceilings.
- Only real benchmark misses remain, each tied to a measured gap.
- Focus areas:
- `scripts/performance-baseline.sh`
- `scripts/correlation-certification.sh`
- `scripts/enterprise-performance-certification.sh`
- Operational performance scorecard output

## Delivery 4: Governance And Operationalization
- Status: Complete
- Closure notes:
- Performance governance now has a single wrapper entrypoint for local and CI certification runs.
- A dedicated GitHub Actions workflow runs certification on schedule, on pull requests, and on manual dispatch, with artifact upload.
- Runtime-role expectations, release gates, ownership, and rollback criteria are documented in the performance governance runbook.
- Goal: make performance a repeatable release gate instead of a one-time effort.
- Exit criteria:
- Certification and scorecard checks are runnable in CI/nightly flows.
- API-versus-worker deployment expectations are documented and testable.
- Rollback and regression criteria are explicit for latency, freshness, and resource ceilings.
- Focus areas:
- Runbooks and release checks.
- Nightly or pre-release automation hooks.
- Ownership for scorecard and SLO regressions.
