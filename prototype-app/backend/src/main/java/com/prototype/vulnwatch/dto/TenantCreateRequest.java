package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record TenantCreateRequest(
        String name,
        String slug,
        String planCode,
        String billingRef,
        boolean addDemoData,
        @Email @Size(max = 255) String ownerEmail,
        @Size(min = 8, max = 72) String ownerPassword
) {
}
