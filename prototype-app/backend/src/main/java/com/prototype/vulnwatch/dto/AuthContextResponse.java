package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public record AuthContextResponse(
        boolean creator,
        String principal,
        String userId,
        String tenantId,
        String tenantName,
        Set<String> roles,
        List<AllowedTenantResponse> allowedTenants,
        boolean platformScope,
        boolean actingAsPlatformOwner,
        boolean sensitiveActionConfirmationRequired,
        String supportAccessMode,
        Instant supportGrantExpiresAt,
        String planCode,
        Boolean demo,
        Instant demoExpiresAt,
        Long demoDaysRemaining,
        java.util.Map<String, Boolean> demoCapabilities,
        java.util.Map<String, Long> demoUsage
) {
}
