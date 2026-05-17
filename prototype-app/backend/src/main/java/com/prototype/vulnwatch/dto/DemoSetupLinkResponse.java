package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record DemoSetupLinkResponse(
        UUID requestId,
        UUID inviteId,
        UUID tenantId,
        String tenantName,
        String email,
        String inviteStatus,
        Instant inviteExpiresAt,
        String inviteUrl,
        String setupUrl
) {
}
