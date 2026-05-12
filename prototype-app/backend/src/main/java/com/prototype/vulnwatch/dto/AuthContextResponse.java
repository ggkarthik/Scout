package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;
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
        String planCode,
        Instant demoExpiresAt,
        Long demoDaysRemaining,
        Map<String, Boolean> demoCapabilities,
        Map<String, Long> demoUsage
) {
}
