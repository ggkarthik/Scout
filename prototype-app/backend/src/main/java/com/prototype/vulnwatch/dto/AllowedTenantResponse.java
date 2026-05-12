package com.prototype.vulnwatch.dto;

public record AllowedTenantResponse(
        String id,
        String name,
        String slug,
        String role
) {
}
