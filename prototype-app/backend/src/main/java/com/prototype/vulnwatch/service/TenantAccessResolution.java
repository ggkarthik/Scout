package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.UUID;

public record TenantAccessResolution(
        Tenant tenant,
        TenantAccessMode mode,
        UUID referenceId,
        String role,
        Instant expiresAt
) {
    public boolean permitsWrite() {
        return mode.permitsWrite();
    }
}
