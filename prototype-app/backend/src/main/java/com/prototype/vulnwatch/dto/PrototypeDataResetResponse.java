package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record PrototypeDataResetResponse(
        Map<String, Long> deletedRows,
        Instant resetAt
) {
}
