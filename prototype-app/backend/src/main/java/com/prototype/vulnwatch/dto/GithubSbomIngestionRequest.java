package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetType;
import jakarta.validation.constraints.NotBlank;

public record GithubSbomIngestionRequest(
        @NotBlank String owner,
        String repo,
        Boolean includeAllRepos,
        AssetType assetType,
        String assetName,
        String assetIdentifier,
        String path
) {
}
