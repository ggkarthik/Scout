package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SccmCmdbConfigResponse(
        UUID id,
        String sourceSystem,
        boolean configured,
        String jdbcUrl,
        String authType,
        String username,
        boolean hasCredential,
        String siteCode,
        String databaseName,
        Integer fetchSize,
        Integer queryTimeoutSeconds,
        boolean mockMode,
        boolean enabled,
        boolean autoSyncEnabled,
        Integer intervalMinutes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
