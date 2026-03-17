package com.prototype.vulnwatch.dto;

public record EolSummaryDto(
        long totalTracked,
        long eolCount,
        long nearEolCount,
        long supportedCount,
        long unknownCount
) {
}
