# CMDB Delta Reconciliation Design

Last updated: 2026-06-24

## Purpose

ServiceNow CMDB ingestion currently behaves as an observed-state upsert pipeline. A successful run creates or updates CIs, assets, software instances, inventory components, and downstream finding deltas for records seen in that run.

That is enough for first ingestion and explicit `active_install=false` rows, but it is not enough for later ingestions where software or assets disappear from the source. Absence is not currently reconciled.

This note defines a safe target design for delta reconciliation without corrupting inventory from other connectors.

## Current Behavior

`ServiceNowCmdbSyncService` fetches ServiceNow discovery model and install rows, enriches install rows, and passes observed rows to `CmdbIngestionService`.

`CmdbInventoryIngestionRunner` then:
- resolves each observed host into `Ci` and `Asset`
- upserts `SoftwareInstance` rows by CI and normalized software key
- upserts `InventoryComponent` rows by asset and normalized component key
- marks observed inventory as active or retired only when the row explicitly says inactive
- updates `lastObservedAt` for touched components
- enqueues finding deltas only for touched components

There is no post-run comparison of active records against the set observed in the current ServiceNow run.

## Problem

After the first successful ingestion, later ingestions can drift:
- new assets and software are created correctly
- changed asset and software details are updated
- explicit inactive install rows are retired correctly
- software missing from the next successful run remains active
- assets missing from the next successful run remain active until the generic stale-asset job marks them inactive

The result is overstated inventory, stale EOL exposure, stale software counts, and findings that may continue to appear for software no longer present.

## Critical Constraint: Provenance

Reconciliation must not operate naively on `inventory_components`.

`inventory_components` is a shared rollup table populated by multiple inventory paths, including SBOM ingestion and CMDB ingestion. It has status, timestamps, and `sbom_upload_id`, but it does not carry direct per-source observation provenance.

Retiring active `inventory_components` merely because ServiceNow did not observe them would be unsafe. It could retire software still observed by GitHub SBOM, SCCM, AWS, or another source.

The safer source-owned table for first-slice reconciliation is `software_instances` because it has:
- `source_system`
- `ci_id`
- `active_install`
- a stable unique key across CI, normalized product, normalized version, and version evidence

Treat `software_instances` as source observations. Treat `inventory_components` as a derived rollup.

## Query Scope Constraint

ServiceNow connector configuration supports `install_query`, `discovery_query`, and table selection. A filtered pull is not necessarily authoritative for the tenant's full CMDB.

Absence reconciliation is safe only inside the connector's authoritative scope:
- the same source system
- the same table/query scope
- the set of CIs included in the current run, or another explicit configured scope
- a completed fetch with no partial failure

If the query changes, reconciliation should not immediately retire records outside the new predicate. The system needs either a scope identity or a guarded transition period.

## Target Design

### 1. Track Source Observations

Add source-observation metadata to CMDB-owned software observations:
- `software_instances.last_observed_at`
- `software_instances.last_reconciled_run_id` or equivalent run marker
- optional `software_instances.source_scope_hash`

The current entity has `updated_at`, but that is not precise enough to distinguish "observed in this source run" from unrelated updates.

### 2. Use a Run Watermark

At the start of a ServiceNow sync, capture `runStartedAt`.

For every observed ServiceNow software instance:
- upsert as today
- set `source_system='servicenow'`
- set `last_observed_at=runStartedAt` or the run observation time
- set `active_install=true` unless the row explicitly says inactive

After the fetch and upsert phase succeeds, reconcile only scoped ServiceNow observations:

```sql
UPDATE software_instances
SET active_install = false,
    updated_at = now()
WHERE source_system = 'servicenow'
  AND ci_id IN (:observedCiIds)
  AND active_install = true
  AND last_observed_at < :runStartedAt;
```

The exact predicate should include source scope once scope identity exists.

### 3. Propagate to the Inventory Rollup

Do not mark an `InventoryComponent` retired simply because ServiceNow no longer sees one instance.

A component should become `RETIRED` only when no active source observation remains for that asset/component identity.

For the first slice, this can be approximated for CMDB-owned host software by:
- finding inventory components linked to reconciled `software_instances`
- checking whether any active `software_instances` still point to the same component
- retiring the component only when no active instance remains
- later extending this to a true per-source observation table that includes SBOM, SCCM, AWS, and other sources

### 4. Enqueue Finding Deltas

Every component retired by reconciliation must enqueue the same finding delta flow used by normal ingestion.

Without this, stale components may disappear from inventory views but continue to drive findings, EOL exposure, and org CVE records.

### 5. Add Grace Against Flapping

ServiceNow install data can lag or flap. Avoid immediate noisy retire/reopen cycles by adding one of:
- consecutive missed run threshold
- configurable grace interval
- soft-retire state before hard retirement

For example, mark an instance `missing_since` on first absence and retire after `N` consecutive complete runs or after a configured duration.

### 6. Asset Reconciliation

Asset-level absence should use CMDB-specific observation metadata, not only the generic stale-asset job.

For ServiceNow-owned hosts:
- update `Asset.lastCmdbSyncAt` when observed
- reconcile missing assets only inside the authoritative ServiceNow scope
- preserve the generic stale-asset job as a backstop, not as the primary CMDB delta mechanism

## Implementation Slices

### Slice 1: Safe Software Reconciliation

- Add `last_observed_at`, `missing_since`, and optional `source_scope_hash` to `software_instances`
- Update CMDB ingestion to stamp observed instances
- After successful complete fetch, mark scoped ServiceNow instances missing or inactive by watermark
- Propagate retirement only when no active software instance remains for the linked component
- Enqueue finding deltas for reconciled components
- Add tests for second-run removal, explicit inactive row, and failed-run no-op

### Slice 2: Source Observation Model

- Introduce a dedicated source observation table for component-level provenance
- Represent observations from ServiceNow, SCCM, SBOM, AWS, and future connectors
- Derive `inventory_components.component_status` from active observations
- Add source-aware audit metadata to explain why a component is active or retired

### Slice 3: Scope Identity and Query Changes

- Persist a normalized connector scope hash from table names and query predicates
- Disable destructive reconciliation on first run after scope changes unless explicitly acknowledged
- Surface scope-change warnings in connector health and sync-run metadata

## Acceptance Criteria

- A second successful ServiceNow run that omits previously observed software retires or marks missing only ServiceNow-scoped software instances.
- GitHub SBOM or other non-ServiceNow components are not retired by ServiceNow absence.
- A failed or partial ServiceNow run does not retire anything by absence.
- A filtered ServiceNow query reconciles only the configured authoritative scope.
- Reconciled retirements enqueue finding deltas.
- Inventory, EOL, software identity summaries, and findings converge after reconciliation.

## Architectural Position

The right mental model is:

`source observations -> derived inventory rollup -> finding/correlation projections`

The current system has pieces of this model, but source observations and the derived rollup are partially collapsed into `inventory_components`. Delta reconciliation should start at the source-observation layer, then update the rollup only when all active observations agree the component is gone.
