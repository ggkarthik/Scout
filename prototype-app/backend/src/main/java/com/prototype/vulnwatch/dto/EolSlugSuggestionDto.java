package com.prototype.vulnwatch.dto;

public record EolSlugSuggestionDto(
        String slug,
        String displayName,
        String confidence,
        String method
) {
}
