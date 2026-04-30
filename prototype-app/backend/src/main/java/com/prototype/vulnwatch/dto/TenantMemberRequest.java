package com.prototype.vulnwatch.dto;

public record TenantMemberRequest(
        String subject,
        String email,
        String displayName,
        String role
) {
}
