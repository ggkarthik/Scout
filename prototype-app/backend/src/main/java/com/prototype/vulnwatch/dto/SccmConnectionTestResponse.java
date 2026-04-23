package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record SccmConnectionTestResponse(
        String status,
        String message,
        boolean systemViewReachable,
        boolean softwareViewReachable,
        Instant testedAt
) {}
