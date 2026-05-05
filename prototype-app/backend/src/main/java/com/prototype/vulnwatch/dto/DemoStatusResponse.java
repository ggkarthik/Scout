package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record DemoStatusResponse(
        boolean demo,
        String planCode,
        Instant demoExpiresAt,
        Long demoDaysRemaining,
        Map<String, Boolean> demoCapabilities,
        Map<String, Long> demoUsage
) {
}
