package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record PlatformUserSetupLinkResponse(
        UUID userId,
        String email,
        String setupUrl
) {
}
