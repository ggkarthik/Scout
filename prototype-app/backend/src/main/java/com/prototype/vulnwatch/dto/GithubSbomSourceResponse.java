package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record GithubSbomSourceResponse(
        UUID id,
        String name,
        String owner,
        String repo,
        String path,
        String assetType,
        String assetName,
        String assetIdentifier,
        String frequency,
        Integer intervalMinutes,
        boolean enabled,
        Instant lastRunAt,
        String lastRunStatus,
        String lastError,
        boolean hasToken
) {
}
