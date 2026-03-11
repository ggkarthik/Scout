package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;

public record GithubAttestationSbomIngestionRequest(
        @NotBlank String owner,
        String repo,
        @NotBlank String imageRepository,
        @NotBlank String subjectDigest,
        String imageTag,
        String assetName,
        String assetIdentifier
) {
}
