package com.prototype.vulnwatch.dto;

public record EolMappingConfirmRequest(
        String normalizedKey,
        String eolSlug
) {
}
