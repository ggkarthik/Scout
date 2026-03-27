package com.prototype.vulnwatch.service;

import java.util.UUID;

public record RequestActor(
        String userId,
        boolean creator,
        UUID tenantId,
        String tenantName
) {
}
