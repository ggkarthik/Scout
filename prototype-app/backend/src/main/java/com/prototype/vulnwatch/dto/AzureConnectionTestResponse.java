package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record AzureConnectionTestResponse(
        String status,
        String message,
        String resolvedTenantId,
        List<String> reachableSubscriptions,
        List<String> warnings,
        Map<String, String> subscriptionErrors,
        Instant testedAt
) {}
