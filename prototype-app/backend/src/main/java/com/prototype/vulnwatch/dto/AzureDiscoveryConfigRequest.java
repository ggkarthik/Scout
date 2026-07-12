package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AzureAuthType;

public record AzureDiscoveryConfigRequest(
        AzureAuthType authType,
        String azureTenantId,
        String clientId,
        /** Secret is only sent when rotating; blank means keep the current value. */
        String credentialSecret,
        String subscriptionIdsJson,
        String regionsJson,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {}
