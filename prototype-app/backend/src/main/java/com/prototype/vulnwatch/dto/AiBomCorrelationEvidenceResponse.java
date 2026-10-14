package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Paths and unresolved gaps are paginated independently using the same page and size. */
public record AiBomCorrelationEvidenceResponse(List<Path> paths, List<Gap> gaps, long pathCount,
        long gapCount, int page, int size, List<Association> associationsWithoutPaths, long associationCount) {
    public record Association(UUID id, UUID findingId, String status, Instant confirmedAt, Instant retiredAt,
            String retirementReason, List<LifecycleEvent> lifecycleHistory) { }
    public record Component(UUID id, String ref, String name, String version) { }
    public record Path(UUID id, UUID findingId, String status, UUID bomId, long sourceRevision,
            List<Component> components, List<UUID> relationshipIds, UUID terminalComponentId,
            String matchMethod, Instant confirmedAt, Instant retiredAt, String retirementReason,
            boolean uncertain, List<LifecycleEvent> lifecycleHistory) { }
    public record LifecycleEvent(String status, Instant at, long revision, UUID bomId,
            Long evidenceRevision, List<UUID> componentIds, List<UUID> relationshipIds) { }
    public record Gap(UUID id, UUID componentId, String componentRef, String reason, String remediation,
            long sourceRevision, Instant detectedAt) { }
}
