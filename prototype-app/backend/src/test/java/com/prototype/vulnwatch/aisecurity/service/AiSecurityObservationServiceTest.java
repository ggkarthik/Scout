package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.transaction.support.TransactionTemplate;

class AiSecurityObservationServiceTest {

    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final AiSecuritySyncRunFacade runs = mock(AiSecuritySyncRunFacade.class);
    private final AiSecurityObservationService service = new AiSecurityObservationService(
            jdbc,
            new ObjectMapper(),
            mock(TenantSchemaExecutionService.class),
            mock(TransactionTemplate.class),
            runs,
            new AiSecurityMetadataSanitizer());

    @Test
    void requiresAzureProviderTenantAssertionBeforeTenantExecution() {
        Tenant tenant = tenant();

        assertThrows(
                IllegalArgumentException.class,
                () -> service.ingest(tenant, envelope(tenant, null)));
    }

    @Test
    void rejectsAzureProviderTenantThatDoesNotMatchConnector() {
        Tenant tenant = tenant();
        when(jdbc.query(
                anyString(),
                any(SqlParameterSource.class),
                org.mockito.ArgumentMatchers.<RowMapper<String>>any()))
                .thenReturn(List.of("configured-entra-tenant"));

        assertThrows(
                IllegalArgumentException.class,
                () -> service.validateCurrentTenantOwnership(
                        tenant, envelope(tenant, "different-entra-tenant")));
        assertDoesNotThrow(() -> service.validateCurrentTenantOwnership(
                tenant, envelope(tenant, "CONFIGURED-ENTRA-TENANT")));
    }

    @Test
    void defaultsKnowledgeAndDataSensitivityToUnknown() {
        var source = new ArtifactObservation("source-1", "DATA_SOURCE", "AZURE_SEARCH_DATA_SOURCES",
                "source", Map.of("sourceType", "AZURE_BLOB"));
        var agent = new ArtifactObservation("agent-1", "AI_AGENT", "AWS_BEDROCK_AGENT",
                "agent", Map.of("status", "PREPARED"));

        assertEquals("UNKNOWN", source.piiScanStatus());
        assertEquals("NOT_APPLICABLE", agent.piiScanStatus());
    }

    private Tenant tenant() {
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(UUID.randomUUID());
        return tenant;
    }

    private ObservationEnvelopeV1 envelope(Tenant tenant, String providerTenantId) {
        UUID runId = UUID.randomUUID();
        UUID connectorId = UUID.randomUUID();
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connectorId,
                tenant.getId(),
                "AZURE",
                providerTenantId,
                "subscription-1",
                "eastus",
                "AZURE_AI_ACCOUNTS",
                "AZURE:subscription-1:eastus:AZURE_AI_ACCOUNTS",
                0,
                1,
                runId + ":scope:0",
                "content-hash",
                Instant.now(),
                ScopeStatus.COMPLETE,
                List.of(),
                List.of(),
                List.of());
    }
}
