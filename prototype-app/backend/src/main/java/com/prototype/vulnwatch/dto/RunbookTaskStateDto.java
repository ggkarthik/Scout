package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record RunbookTaskStateDto(
        String taskId,
        String state,        // "DONE" | "READY"
        String producedBy,   // "ANALYST" | "AGENT"
        String confidence,   // "HIGH" | "MEDIUM" | "LOW" — null when producedBy=ANALYST
        Instant completedAt
) {}
