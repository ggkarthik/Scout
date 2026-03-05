package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;

public record FindingCommentRequest(
        @NotBlank String author,
        @NotBlank String body
) {
}
