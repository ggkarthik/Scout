package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record AwsConnectionTestResponse(
        String status,
        String message,
        String resolvedAccountId,
        List<String> reachableRegions,
        Instant testedAt
) {}
