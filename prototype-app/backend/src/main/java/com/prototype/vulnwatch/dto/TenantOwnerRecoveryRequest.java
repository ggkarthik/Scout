package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TenantOwnerRecoveryRequest(
        @NotBlank @Email @Size(max = 255) String ownerEmail,
        @NotBlank @Size(min = 8, max = 72) String ownerPassword
) {
}
