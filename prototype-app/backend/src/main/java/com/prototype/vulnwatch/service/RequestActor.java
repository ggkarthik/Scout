package com.prototype.vulnwatch.service;

import java.util.Set;
import java.util.UUID;

public record RequestActor(
        String userId,
        boolean creator,
        UUID tenantId,
        String tenantName,
        Set<String> roles
) {
    public RequestActor(String userId, boolean creator, UUID tenantId, String tenantName) {
        this(userId, creator, tenantId, tenantName, Set.of());
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
}
