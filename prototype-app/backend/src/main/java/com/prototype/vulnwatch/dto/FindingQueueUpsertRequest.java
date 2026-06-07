package com.prototype.vulnwatch.dto;

public record FindingQueueUpsertRequest(
        String title,
        String description,
        FindingsFilter filter,
        Integer displayOrder,
        String sourceQueueKey,
        Boolean setAsDefault
) {
}
