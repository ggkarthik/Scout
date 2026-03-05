package com.prototype.vulnwatch.dto;

public record AuthContextResponse(
        boolean creator,
        String principal
) {
}
