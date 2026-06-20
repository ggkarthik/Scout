package com.prototype.vulnwatch.service.cbom;

public record CbomIngestionResult(
        int componentCount,
        int findingCount
) {}
