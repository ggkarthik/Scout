package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AwsDiscoveryConfigResponse(
        UUID id,
        String sourceSystem,
        boolean configured,
        String authType,
        String accessKeyId,
        /** Never the raw secret — only indicates whether one has been stored. */
        boolean hasCredential,
        String crossAccountRoleArn,
        String externalId,
        String awsAccountId,
        String regionsJson,
        String resourceTypesJson,
        boolean enabled,
        boolean autoSyncEnabled,
        int intervalMinutes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
