package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record OperationalSectionResponse<T>(
        Instant generatedAt,
        T data
) {
}
