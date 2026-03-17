package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record OrgSpecificCveExposureRecordResponse(
        UUID recordId,
        UUID vulnerabilityId,
        String externalId,
        String title,
        String applicability,
        boolean impacted,
        String impactState,
        String impactReason,
        String reviewReason,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        long matchedComponentCount,
        long matchedSoftwareCount,
        long matchedAssetCount,
        long applicableComponentCount,
        long impactedComponentCount,
        long notAffectedComponentCount,
        long fixedComponentCount,
        long noPatchComponentCount,
        long underInvestigationComponentCount,
        long unknownComponentCount,
        long openFindings,
        Instant lastEvaluatedAt,
        long eolComponentCount,
        long eosComponentCount
) {
}
