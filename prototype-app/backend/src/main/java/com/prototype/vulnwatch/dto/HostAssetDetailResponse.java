package com.prototype.vulnwatch.dto;

import java.util.List;

public record HostAssetDetailResponse(
        HostAssetSummaryResponse host,
        List<HostAliasResponse> aliases,
        List<HostSoftwareInstanceResponse> software,
        List<HostFindingResponse> findings,
        List<HostApplicableCveResponse> applicableCves
) {
}
