package com.prototype.vulnwatch.dto;

import java.util.List;

public record FindingDistributionsResponse(
        List<FindingCountBucketResponse> severityCounts,
        List<FindingCountBucketResponse> statusCounts,
        List<FindingAssetCountResponse> topAssets
) {
}
