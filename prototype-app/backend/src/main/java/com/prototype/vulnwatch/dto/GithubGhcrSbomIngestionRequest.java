package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;

public record GithubGhcrSbomIngestionRequest(
        @NotBlank String owner
) {
}
