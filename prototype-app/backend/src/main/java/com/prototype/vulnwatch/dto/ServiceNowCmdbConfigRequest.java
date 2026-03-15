package com.prototype.vulnwatch.dto;

public record ServiceNowCmdbConfigRequest(
        String baseUrl,
        String authType,
        String username,
        String credentialSecret,
        String installTable,
        String discoveryModelTable,
        String ciTable,
        String installQuery,
        String discoveryQuery,
        String installFields,
        String discoveryFields,
        Integer pageSize,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {
}
