package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SuppressionRuleResponse(
        UUID id,
        String name,
        String state,
        String recordType,
        String conditionsJson,
        String conditionLogic,
        String reason,
        Instant validFrom,
        Instant validTo,
        Instant createdAt,
        Instant updatedAt,
        long suppressedCount
) {
}
