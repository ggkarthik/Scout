package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AzureDiscoveryConfigResponse(
        UUID id,
        String sourceSystem,
        boolean configured,
        String authType,
        String azureTenantId,
        String clientId,
        boolean hasCredential,
        String subscriptionIdsJson,
        String regionsJson,
        boolean enabled,
        boolean autoSyncEnabled,
        int intervalMinutes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
