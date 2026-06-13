package com.prototype.vulnwatch.dto;

public record TenantMemberUpdateRequest(
        String role,
        String status
) {
}
