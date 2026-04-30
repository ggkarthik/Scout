package com.prototype.vulnwatch.dto;

import java.util.Set;

public record AuthContextResponse(
        boolean creator,
        String principal,
        String userId,
        String tenantId,
        String tenantName,
        Set<String> roles
) {
}
