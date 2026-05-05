package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record DemoRequestResponse(
        UUID id,
        String email,
        String fullName,
        String company,
        String roleTitle,
        String companySize,
        String useCase,
        String notes,
        String status,
        Instant requestedAt,
        Instant decidedAt,
        String decidedBy,
        String rejectionReason,
        UUID tenantId,
        DemoInviteResponse latestInvite
) {
}
