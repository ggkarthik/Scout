package com.prototype.vulnwatch.dto;

import java.util.List;

public record GithubSbomIngestionBatchResponse(
        int repositoriesDiscovered,
        int repositoriesProcessed,
        int repositoriesSucceeded,
        int repositoriesFailed,
        int componentsIngested,
        int findingsGenerated,
        List<GithubRepoIngestionResult> results
) {
}
