package com.prototype.vulnwatch.dto;

public record AwsDiscoveryConfigRequest(
        String authType,
        String accessKeyId,
        /** Secret access key — only sent when rotating; blank = keep existing value. */
        String credentialSecret,
        String crossAccountRoleArn,
        String externalId,
        String regionsJson,
        String resourceTypesJson,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {}
