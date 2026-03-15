package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record ServiceNowCmdbConnectionTestResponse(
        String status,
        String message,
        boolean ciTableReachable,
        boolean installTableReachable,
        boolean discoveryTableReachable,
        Instant testedAt
) {
}
