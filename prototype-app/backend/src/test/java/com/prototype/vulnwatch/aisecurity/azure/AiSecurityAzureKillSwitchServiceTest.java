package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class AiSecurityAzureKillSwitchServiceTest {

    @Test
    void appliesTenantConnectorFamilyAndPolicyControlsIndependently() {
        UUID tenantId = UUID.randomUUID();
        UUID connectorId = UUID.randomUUID();
        AiSecurityAzureKillSwitchService service = new AiSecurityAzureKillSwitchService(
                tenantId.toString(),
                connectorId.toString(),
                "azure_ml_jobs",
                "azure_ai_local_auth_enabled");

        assertThrows(
                AiSecurityAzureKillSwitchService.DiscoveryDisabledException.class,
                () -> service.assertDiscoveryAllowed(tenantId, UUID.randomUUID()));
        assertThrows(
                AiSecurityAzureKillSwitchService.DiscoveryDisabledException.class,
                () -> service.assertDiscoveryAllowed(UUID.randomUUID(), connectorId));
        assertTrue(service.isResourceFamilyDisabled("AZURE_ML_JOBS"));
        assertTrue(service.isPolicyDisabled("AZURE_AI_LOCAL_AUTH_ENABLED"));
        assertFalse(service.isResourceFamilyDisabled("AZURE_AI_ACCOUNTS"));
        assertFalse(service.isPolicyDisabled("AWS_BEDROCK_PUBLIC_KB_S3"));
    }
}
