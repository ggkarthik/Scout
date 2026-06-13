package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record OperationalDemoPurgeDryRunCandidateResponse(
        UUID tenantId,
        String tenantName,
        String schemaName,
        Instant demoExpiresAt,
        String status,
        String purgeStatus,
        boolean eligible,
        String eligibilityReason
) {
}
