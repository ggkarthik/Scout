package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record BomFetchRequest(
        @NotNull BomType bomType,
        @NotNull AssetType assetType,
        @NotBlank String assetName,
        @NotBlank String assetIdentifier,
        @NotBlank String sourceUrl,
        String sourceLabel,
        String supplier,
        String authorizationHeader
) {}
