package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.GithubIngestionFrequency;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public record GithubSbomSourceRequest(
        @NotBlank String name,
        @NotBlank String owner,
        String repo,
        String path,
        AssetType assetType,
        String assetName,
        String assetIdentifier,
        GithubIngestionFrequency frequency,
        @Min(5) @Max(1440) Integer intervalMinutes,
        Boolean enabled,
        String githubToken
) {
}
