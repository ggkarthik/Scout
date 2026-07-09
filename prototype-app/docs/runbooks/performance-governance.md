# Performance Governance Runbook

Last updated: 2026-07-09

## Purpose

This runbook turns Scout performance validation into a repeatable release gate instead of an ad hoc local check.

It covers:

- the automation entrypoints for baseline, correlation, and scorecard certification
- when to run them in CI, nightly, and pre-release flows
- the runtime-role expectations for API nodes versus worker-capable nodes
- the rollback and regression criteria that block or reverse a release

## Automation Entry Points

Primary wrapper:

- `prototype-app/scripts/run-performance-governance.sh`

Underlying certification helpers:

- `prototype-app/scripts/performance-baseline.sh`
- `prototype-app/scripts/correlation-certification.sh`
- `prototype-app/scripts/performance-scorecard.sh`
- `prototype-app/scripts/enterprise-performance-certification.sh`

GitHub Actions workflow:

- `.github/workflows/performance-governance.yml`

## When To Run

Nightly:

- The `Performance Governance` workflow runs on a daily schedule.
- Purpose: catch drift in route latency, freshness, queue stability, and resource ceilings before a release train forms around it.

Pull request validation:

- The same workflow also runs on pull requests for changes under `prototype-app/backend`, `prototype-app/scripts`, `prototype-app/docs`, and the workflow itself.
- Purpose: catch certification regressions before they land on a protected branch.

Manual:

- Use `workflow_dispatch` in GitHub for an on-demand certification pass.
- Override `seed_demo_data` or `baseline_iterations` if you need a narrower or heavier validation pass.
- `seed_demo_data` defaults to `false` and should only be enabled for approved non-production certification environments.

Local operator run:

```bash
cd prototype-app
BASE_URL=http://127.0.0.1:8080 \
API_KEY=change-me-in-prod \
CREATOR_KEY=local-creator \
START_BACKEND=true \
SPRING_PROFILES_ACTIVE=local \
MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus \
sh ./scripts/run-performance-governance.sh
```

## Runtime Expectations

Interactive API nodes:

- Set `APP_RUNTIME_ROLE=api`.
- This suppresses queue pollers, scheduled recompute work, and other worker-side background execution on user-facing nodes.
- The behavior is enforced by `BackgroundTaskExecutionPolicy` in [BackgroundTaskExecutionPolicy.java](/Users/gowrikarthik.gadela/Desktop/AI%20Projects/NoScan/Scout/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/BackgroundTaskExecutionPolicy.java).

Worker-capable nodes:

- Use `APP_RUNTIME_ROLE=worker` or leave the setting as the default `all` in single-node environments.
- These nodes are allowed to run scheduled and queue-driven background work.

Certification runtime:

- Use `SPRING_PROFILES_ACTIVE=local` for local and CI certification runs.
- Reason: the certification scripts need tenant-scoped route access and local JWT login support in order to collect real route metrics instead of tenant-context guardrail responses.
- When Prometheus is not part of the environment default, set `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus` only for that approved local or certification run.

## Release Gates

A certification run is release-pass only when all of the following are true:

- Baseline route sampling succeeds with no route failures and no auth-skip-only routes.
- Final `/api/operations/performance-scorecard` is `overallCompliant=true`.
- Final `/api/slo/status` is `overallCompliant=true`.
- `routeFailureCount=0`.
- `freshnessFailureCount=0`.
- `resourceFailureCount=0`.
- `resourceNoDataCount=0`.
- `pendingEventCount`, `processingEventCount`, and `ingestionQueuedJobCount` do not grow beyond the configured allowed growth.
- `projection_stale=false`.
- `scoutgrid.finding_delta_queue.oldest_age_seconds <= 600`.
- `scoutgrid.finding_projection.max_lag_seconds <= 900`.
- Failed delta-event history does not grow beyond the configured `MAX_FAILED_GROWTH` threshold during the run.

## Artifact Review

Primary artifacts emitted by a governance run:

- `certification-summary.txt`
- `baseline/route-summary.tsv`
- `correlation/correlation-certification-summary.tsv`
- `final-scorecard/performance-scorecard.json`
- `run-manifest.txt`

Start with `certification-summary.txt`, then inspect:

- `route-summary.tsv` for request coverage and route failures
- `correlation-certification-summary.tsv` for queue/freshness drift and failed-event growth
- `performance-scorecard.json` for route, freshness, and resource breakdowns

## Rollback Criteria

Rollback the candidate release or stop rollout immediately if any of these happen after deploy:

- route latency or scorecard compliance regresses from green to red
- freshness SLOs become non-compliant
- queue backlog or oldest queue age exceeds the certification threshold
- projection lag exceeds the certification threshold
- API-serving nodes are discovered running worker-grade background tasks unintentionally
- certification artifacts cannot be produced because the deployment no longer exposes the required operational endpoints

## Rollback Actions

1. Roll the backend deployment back to the previous image or release artifact.
2. Confirm API-serving nodes are running with `APP_RUNTIME_ROLE=api`.
3. Confirm worker-capable nodes are isolated to `worker` or `all`.
4. Re-run the performance scorecard and correlation certification helpers.
5. Do not resume rollout until scorecard and SLO compliance return to green.

## Ownership

Primary owners:

- Backend/platform engineering owns the workflow, scripts, and release gate behavior.
- The release owner is responsible for checking certification artifacts before broad rollout.

Escalation ownership:

- Queue/freshness regressions: backend/platform engineering
- Resource ceiling regressions: backend/platform engineering
- Workflow or artifact failures: developer productivity / platform engineering

## Notes

- `performance-baseline.sh` is intentionally strict now: auth-skip-only route sampling is treated as an invalid certification run, not a pass.
- `correlation-certification.sh` intentionally evaluates failed-event growth from the start of the run so historical residue does not permanently poison fresh certification passes.
