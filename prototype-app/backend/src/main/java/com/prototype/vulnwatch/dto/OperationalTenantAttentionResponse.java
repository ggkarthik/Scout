package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record OperationalTenantAttentionResponse(
        UUID tenantId,
        String tenantName,
        String tenantStatus,
        List<String> reasons,
        List<String> affectedConnectors,
        Instant latestRelevantSyncAt
) {
}
