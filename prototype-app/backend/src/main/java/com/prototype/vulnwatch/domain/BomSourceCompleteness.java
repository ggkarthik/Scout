package com.prototype.vulnwatch.domain;

/**
 * What a BOM source claims to describe.
 *
 * <p>Only {@link #COMPLETE_ASSET_SOFTWARE} lets a later replacement record authoritative
 * absence, which is the sole path that may retire a component. It is an audited assertion,
 * not a convenience flag, and it says nothing about AI model coverage.
 */
public enum BomSourceCompleteness {
    PARTIAL,
    COMPLETE_ASSET_SOFTWARE
}
