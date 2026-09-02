package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

class AiGridValidationGovernanceServiceTest {
    @Test
    void rejectsPrecisionSamplesWithoutImmutableTenantRunProvenance() {
        AiGridValidationGovernanceService service = new AiGridValidationGovernanceService(
                org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class),
                org.mockito.Mockito.mock(TransactionTemplate.class), new ObjectMapper(),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.service.TenantSchemaExecutionService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.service.TenantService.class));

        ResponseStatusException error = assertThrows(ResponseStatusException.class, () -> service.addPrecisionSample(
                UUID.randomUUID(), new AiGridValidationGovernanceService.PrecisionSampleCommand(
                "unbound", "AWS", "BEDROCK_AGENTS", "HIGH", "FAIL", true, "review://unbound")));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        assertEquals("Precision samples require sourceTenantId, sourceRunId, and sourceAssessmentId", error.getReason());
    }
}
