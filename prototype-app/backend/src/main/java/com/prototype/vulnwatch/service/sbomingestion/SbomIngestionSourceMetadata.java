package com.prototype.vulnwatch.service.sbomingestion;

public record SbomIngestionSourceMetadata(
        String sourceType,
        String sourceSystem,
        String sourceReference,
        String sourceEndpoint,
        Integer fetchStatusCode,
        String contentType,
        Long contentLengthBytes,
        String evidenceJson
) {
}
