package com.prototype.vulnwatch.service.sbomingestion;

public record SbomEndpointFetchResult(
        byte[] content,
        SbomIngestionSourceMetadata metadata
) {
}
