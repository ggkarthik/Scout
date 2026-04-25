package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AwsDiscoveryTargetResponse(
        UUID id,
        String accountId,
        String accountName,
        String roleArn,
        String externalId,
        boolean enabled,
        String regionsJson,
        String resourceTypesJson,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt,
        long hostCount,
        long ssmManagedHostCount,
        long missingIamInstanceProfileCount,
        long softwareInventoryHostCount
) {}
