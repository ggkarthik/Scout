package com.prototype.vulnwatch.dto;

public record AzureDiscoveryTargetRequest(
        String subscriptionId,
        String subscriptionName,
        Boolean enabled,
        String regionsJson
) {}
