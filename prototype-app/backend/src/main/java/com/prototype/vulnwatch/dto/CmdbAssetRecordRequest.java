package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CmdbAssetRecordRequest(
        @NotNull AssetType assetType,
        @NotBlank String assetName,
        @NotBlank String assetIdentifier,
        String serviceName,
        String environment,
        String ownerTeam,
        String ownerEmail,
        BusinessCriticality businessCriticality,
        AssetState state,
        // BLG-011: OCI/container artifact fields (only meaningful for CONTAINER_IMAGE assets)
        String imageDigest,
        String imageTag,
        String imageRepository,
        String baseImageDigest
) {
}
