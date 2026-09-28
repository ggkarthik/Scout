package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.BomSourceCompleteness;

import java.util.Set;
import java.util.UUID;

/**
 * Which logical source an incoming BOM document belongs to, and what it claims.
 *
 * <p>Three shapes, in precedence order:
 * <ul>
 *   <li>{@code sourceId} -- replace this named source's current version.</li>
 *   <li>{@code sourceKey} -- an automated caller's deterministic identity, so a scheduled
 *       run replaces its own source instead of adding one per run.</li>
 *   <li>neither -- an independent source. Nothing is implicitly replaced.</li>
 * </ul>
 *
 * @param actorRoles roles of the caller, checked before a completeness claim is honoured
 * @param assertedBy identity recorded on the completeness assertion audit row
 */
public record BomSourceSelector(
        UUID sourceId,
        String sourceKey,
        BomSourceCompleteness completeness,
        Set<String> actorRoles,
        String assertedBy
) {

    /** A manual upload that names no source: creates a new, independent one. */
    public static BomSourceSelector independent() {
        return new BomSourceSelector(null, null, BomSourceCompleteness.PARTIAL, Set.of(), null);
    }

    /**
     * An automated caller identifying its own source. Always PARTIAL: completeness is an
     * audited human assertion, never something a scheduled job claims on its own.
     */
    public static BomSourceSelector keyed(String sourceKey) {
        return new BomSourceSelector(null, sourceKey, BomSourceCompleteness.PARTIAL, Set.of(), null);
    }
}
