package com.prototype.vulnwatch.dto;

public record GithubRepoIngestionResult(
        String owner,
        String repo,
        String assetIdentifier,
        String status,
        Integer componentsIngested,
        Integer findingsGenerated,
        String message
) {
}
