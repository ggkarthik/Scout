package com.prototype.vulnwatch.dto;

import java.util.Set;

public record TestPersonaResponse(
        String key,
        String label,
        String subject,
        String tenantSlug,
        String tenantName,
        Set<String> roles
) {
}
