package com.prototype.vulnwatch.dto;

public record TenantInviteRequest(
        String email,
        String displayName,
        String role
) {
}
