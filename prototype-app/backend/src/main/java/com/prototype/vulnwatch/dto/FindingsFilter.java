package com.prototype.vulnwatch.dto;

import java.util.List;

/**
 * Canonical findings filter contract shared by records, analytics, and future
 * saved/shared queue definitions.
 */
public record FindingsFilter(
        List<String> severity,
        List<String> status,
        List<String> decisionState,
        List<String> creationSource,
        List<String> matchMethod,
        List<String> vexStatus,
        List<String> vexFreshness,
        List<String> vexProvider,
        Double minConfidence,
        String vulnerabilityId,
        String packageName,
        String ecosystem,
        String ownerGroup,
        String assignedTo,
        Boolean unassignedOnly,
        Boolean incidentLinked,
        String dueDateBand,
        String assetName,
        String supportGroup,
        Boolean patchAvailable,
        String suppressedUntilBand,
        List<String> assetType
) {
    /** Backward-compatible constructor for call sites predating the {@code assetType} filter. */
    public FindingsFilter(
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> creationSource,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem,
            String ownerGroup,
            String assignedTo,
            Boolean unassignedOnly,
            Boolean incidentLinked,
            String dueDateBand,
            String assetName,
            String supportGroup,
            Boolean patchAvailable,
            String suppressedUntilBand
    ) {
        this(
                severity, status, decisionState, creationSource, matchMethod, vexStatus, vexFreshness,
                vexProvider, minConfidence, vulnerabilityId, packageName, ecosystem, ownerGroup, assignedTo,
                unassignedOnly, incidentLinked, dueDateBand, assetName, supportGroup, patchAvailable,
                suppressedUntilBand, null
        );
    }
}
