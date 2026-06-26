package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record AwsConnectionTestResponse(
        String status,
        String message,
        String resolvedAccountId,
        List<String> reachableRegions,
        List<String> warnings,
        Map<String, String> regionErrors,
        Instant testedAt
) {}
