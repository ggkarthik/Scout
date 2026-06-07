package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record FindingQueueDefinitionResponse(
        UUID id,
        String key,
        String title,
        String description,
        String kind,
        String ownerType,
        boolean editable,
        boolean isDefault,
        long matchingCount,
        FindingsFilter filter,
        FindingSummaryResponse summary
) {
}
