package com.prototype.vulnwatch.domain;

/**
 * A single source's standing claim about one inventory component.
 *
 * <p>{@link #WITHDRAWN} means this source no longer vouches for the component. It does not
 * mean the component is absent: other sources may still support it, and absence requires
 * authoritative absence under an asserted complete scope.
 */
public enum BomContributionState {
    SUPPORTED,
    WITHDRAWN
}
