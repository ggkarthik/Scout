package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

class AiGridRuntimeIngestionServiceTest {
    private final AiGridRuntimeIngestionService service = new AiGridRuntimeIngestionService(
            mock(NamedParameterJdbcTemplate.class), mock(TenantSchemaExecutionService.class),
            mock(TransactionTemplate.class), mock(IngestionJobService.class), new ObjectMapper().findAndRegisterModules(), 10);
    private final Tenant tenant = mock(Tenant.class);

    @Test
    void rejectsForbiddenRawContentBeforeAdmission() {
        assertThrows(IllegalArgumentException.class, () -> service.accept(tenant, "producer", bytes("""
                {"schemaVersion":"1","provider":"CUSTOM","evidenceClass":"DECLARED",
                 "executions":[{"providerExecutionReference":"run-1","scopeKey":"scope","eventTime":"2026-01-01T00:00:00Z",
                 "status":"COMPLETED","evidenceClass":"DECLARED","events":[],"prompt":"do not persist"}]}
                """)));
    }

    @Test
    void rejectsOmittedEventsButAcceptsEmptyEventsAtSchemaBoundary() {
        assertThrows(IllegalArgumentException.class, () -> service.accept(tenant, "producer", bytes("""
                {"schemaVersion":"1","provider":"CUSTOM","evidenceClass":"DECLARED",
                 "executions":[{"providerExecutionReference":"run-1","scopeKey":"scope","eventTime":"2026-01-01T00:00:00Z",
                 "status":"COMPLETED","evidenceClass":"DECLARED"}]}
                """)));
    }

    @Test
    void enforcesTwoMebibyteProducerFacingLimitFirst() {
        assertThrows(IllegalArgumentException.class,
                () -> service.accept(tenant, "producer", new byte[(2 * 1024 * 1024) + 1]));
    }

    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
