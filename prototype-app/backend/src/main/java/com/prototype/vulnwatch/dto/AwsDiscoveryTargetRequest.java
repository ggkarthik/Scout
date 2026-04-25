package com.prototype.vulnwatch.dto;

public record AwsDiscoveryTargetRequest(
        String accountId,
        String accountName,
        String roleArn,
        String externalId,
        Boolean enabled,
        String regionsJson,
        String resourceTypesJson
) {}
