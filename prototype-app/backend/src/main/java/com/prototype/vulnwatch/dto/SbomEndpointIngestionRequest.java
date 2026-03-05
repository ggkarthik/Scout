package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SbomEndpointIngestionRequest(
        @NotNull AssetType assetType,
        @NotBlank String assetName,
        @NotBlank String assetIdentifier,
        @NotBlank String sourceUrl,
        String sourceLabel,
        String authorizationHeader
) {
}
