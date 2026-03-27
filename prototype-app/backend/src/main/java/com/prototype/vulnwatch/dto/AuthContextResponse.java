package com.prototype.vulnwatch.dto;

public record AuthContextResponse(
        boolean creator,
        String principal,
        String userId,
        String tenantId,
        String tenantName
) {
}
