package com.prototype.vulnwatch.domain;

/** Per-asset gate for contribution backfill. Reconciliation may only infer absence when BACKFILLED. */
public enum BomBackfillState {
    PENDING,
    BACKFILLED,
    FAILED
}
