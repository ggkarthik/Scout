package com.prototype.vulnwatch.dto;

public record SccmCmdbConfigRequest(
        String jdbcUrl,
        String authType,
        String username,
        String credentialSecret,
        String siteCode,
        String databaseName,
        Integer fetchSize,
        Integer queryTimeoutSeconds,
        Boolean mockMode,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {}
