package com.prototype.vulnwatch.dto;

public record CmdbAssetSyncResponse(
        int received,
        int inserted,
        int updated,
        String message
) {
}
