package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;

public record PlatformOwnerTenantMembershipRequest(
        @NotBlank String subject,
        @NotBlank String role
) {
}
