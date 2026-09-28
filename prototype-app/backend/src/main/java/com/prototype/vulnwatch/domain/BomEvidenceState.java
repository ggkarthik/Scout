package com.prototype.vulnwatch.domain;

/**
 * Aggregate of every source's claims about a component, kept separate from its
 * ACTIVE/RETIRED status: status is presence, this is what the evidence says about presence.
 */
public enum BomEvidenceState {
    /** At least one source currently vouches for it. */
    SUPPORTED,
    /** A complete replacement asserted absence while another source still reports it. */
    CONFLICTING,
    /** Every claim has been withdrawn. Presence is unknown, not disproved. */
    WITHDRAWN,
    /** Predates contribution tracking, or its asset is not yet backfilled. Never retire. */
    LEGACY_UNKNOWN
}
