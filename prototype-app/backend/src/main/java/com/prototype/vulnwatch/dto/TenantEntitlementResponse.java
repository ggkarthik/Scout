package com.prototype.vulnwatch.dto;

import java.util.Map;

public record TenantEntitlementResponse(
        String key,
        String category,
        boolean enabled,
        String source,
        String planCode,
        Map<String, Object> config
) {
}
