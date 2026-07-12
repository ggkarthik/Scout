package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AzureDiscoveryTargetResponse(
        UUID id,
        String subscriptionId,
        String subscriptionName,
        boolean enabled,
        String regionsJson,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt,
        long hostCount
) {}
