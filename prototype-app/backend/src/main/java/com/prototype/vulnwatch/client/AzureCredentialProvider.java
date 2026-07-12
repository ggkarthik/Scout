package com.prototype.vulnwatch.client;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.prototype.vulnwatch.domain.AzureAuthType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;

public final class AzureCredentialProvider {

    private AzureCredentialProvider() {
    }

    public static TokenCredential from(AzureDiscoveryConfig config) {
        AzureAuthType authType = config.getAuthType() == null
                ? AzureAuthType.CLIENT_SECRET
                : config.getAuthType();

        return switch (authType) {
            case MANAGED_IDENTITY -> buildManagedIdentity(config);
            case CLIENT_SECRET -> buildClientSecret(config);
        };
    }

    private static TokenCredential buildClientSecret(AzureDiscoveryConfig config) {
        String tenantId = config.getAzureTenantId();
        String clientId = config.getClientId();
        String clientSecret = config.getClientSecret();
        if (!hasText(tenantId) || !hasText(clientId) || !hasText(clientSecret)) {
            throw new IllegalStateException(
                    "AZURE_DISCOVERY: CLIENT_SECRET auth requires azureTenantId, clientId, and credentialSecret.");
        }
        return new ClientSecretCredentialBuilder()
                .tenantId(tenantId.trim())
                .clientId(clientId.trim())
                .clientSecret(clientSecret.trim())
                .build();
    }

    private static TokenCredential buildManagedIdentity(AzureDiscoveryConfig config) {
        DefaultAzureCredentialBuilder builder = new DefaultAzureCredentialBuilder();
        if (hasText(config.getClientId())) {
            builder.managedIdentityClientId(config.getClientId().trim());
        }
        return builder.build();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
