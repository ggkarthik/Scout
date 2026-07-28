package com.prototype.vulnwatch.aisecurity.azure;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityAzureKillSwitchService {

    private final Set<String> disabledTenantIds;
    private final Set<String> disabledConnectorIds;
    private final Set<String> disabledResourceFamilies;
    private final Set<String> disabledPolicyIds;

    public AiSecurityAzureKillSwitchService(
            @Value("${app.ai-security.azure.disabled-tenant-ids:}") String disabledTenantIds,
            @Value("${app.ai-security.azure.disabled-connector-ids:}") String disabledConnectorIds,
            @Value("${app.ai-security.azure.disabled-resource-families:}") String disabledResourceFamilies,
            @Value("${app.ai-security.azure.disabled-policy-ids:}") String disabledPolicyIds
    ) {
        this.disabledTenantIds = identifiers(disabledTenantIds);
        this.disabledConnectorIds = identifiers(disabledConnectorIds);
        this.disabledResourceFamilies = names(disabledResourceFamilies);
        this.disabledPolicyIds = names(disabledPolicyIds);
    }

    public void assertDiscoveryAllowed(UUID tenantId, UUID connectorId) {
        if (tenantId != null && disabledTenantIds.contains(tenantId.toString().toLowerCase(Locale.ROOT))) {
            throw new DiscoveryDisabledException("Azure AI Security discovery is disabled for this tenant");
        }
        if (connectorId != null && disabledConnectorIds.contains(connectorId.toString().toLowerCase(Locale.ROOT))) {
            throw new DiscoveryDisabledException("Azure AI Security discovery is disabled for this connector");
        }
    }

    public boolean isResourceFamilyDisabled(String resourceFamily) {
        return resourceFamily != null
                && disabledResourceFamilies.contains(resourceFamily.trim().toUpperCase(Locale.ROOT));
    }

    public boolean isPolicyDisabled(String policyId) {
        return policyId != null && disabledPolicyIds.contains(policyId.trim().toUpperCase(Locale.ROOT));
    }

    private Set<String> identifiers(String value) {
        return split(value).stream().map(item -> item.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    private Set<String> names(String value) {
        return split(value).stream().map(item -> item.toUpperCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    private Set<String> split(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }

    public static class DiscoveryDisabledException extends RuntimeException {
        public DiscoveryDisabledException(String message) {
            super(message);
        }
    }
}
