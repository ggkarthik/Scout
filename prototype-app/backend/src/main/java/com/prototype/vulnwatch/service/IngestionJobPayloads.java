package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.AssetType;
import java.util.UUID;

final class IngestionJobPayloads {

    private IngestionJobPayloads() {
    }

    record EndpointIngestionPayload(
            BomType bomType,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            String sourceUrl,
            String sourceLabel,
            String supplier,
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
            UUID sourceId,
            String path
    ) {
    }

    record GithubGhcrIngestionPayload(
            String owner,
            UUID syncRunId,
            UUID sourceId
    ) {
    }
}
