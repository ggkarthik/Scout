package com.prototype.vulnwatch.domain;

/** Scheduling state of a logical BOM source. */
public enum BomSourceState {
    ACTIVE,
    /** Tenant lacks the AI Security entitlement; ordinary ingestion continues regardless. */
    HELD_ENTITLEMENT,
    /** Admitted but deferred behind the per-tenant projection backlog cap. */
    DEFERRED
}
