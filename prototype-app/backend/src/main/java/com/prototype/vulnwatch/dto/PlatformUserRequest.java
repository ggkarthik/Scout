package com.prototype.vulnwatch.dto;

public record PlatformUserRequest(
        String externalSubject,
        String email,
        String displayName,
        String role
) {
}
