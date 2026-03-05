package com.prototype.vulnwatch.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record CmdbAssetSyncRequest(
        @NotNull @Valid List<CmdbAssetRecordRequest> assets
) {
}
