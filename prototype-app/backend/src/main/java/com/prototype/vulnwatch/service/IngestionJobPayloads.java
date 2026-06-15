package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import java.util.UUID;

final class IngestionJobPayloads {

    private IngestionJobPayloads() {
    }

    record EndpointIngestionPayload(
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            String sourceUrl,
            String sourceLabel,
            String encryptedAuthorizationHeader
    ) {
    }

    record GithubRepositoryIngestionPayload(
            String owner,
            String repo,
            Boolean includeAllRepos,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            UUID syncRunId,
            UUID sourceId
    ) {
    }

    record GithubGhcrIngestionPayload(
            String owner,
            UUID syncRunId,
            UUID sourceId
    ) {
    }
}
