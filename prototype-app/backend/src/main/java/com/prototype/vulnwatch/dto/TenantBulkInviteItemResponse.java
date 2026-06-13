package com.prototype.vulnwatch.dto;

public record TenantBulkInviteItemResponse(
        String email,
        String displayName,
        String role,
        String status,
        String message,
        TenantInviteResponse invite
) {
}
