package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record OwnershipRuleResponse(
        UUID id,
        String name,
        String condition,
        String userGroup,
        int executionOrder,
        long matchedCount,
        Instant createdAt,
        Instant updatedAt
) {}
