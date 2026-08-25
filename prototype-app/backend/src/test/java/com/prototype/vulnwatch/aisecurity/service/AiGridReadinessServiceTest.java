package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridReadinessServiceTest {
    @Test
    void capabilityGapsBecomeConnectorSetupActions() throws Exception {
        AiGridReadinessService service = new AiGridReadinessService(
                org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class), new ObjectMapper(),
                org.mockito.Mockito.mock(TenantSchemaExecutionService.class),
                org.mockito.Mockito.mock(AiGridCoverageService.class));
        Class<?> gapType = Class.forName(AiGridReadinessService.class.getName() + "$Gap");
        Constructor<?> constructor = gapType.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object gap = constructor.newInstance("fingerprint", UUID.randomUUID(), "AGCF-AWS-001",
                "CAPABILITY_UNAVAILABLE", "capability:BEDROCK_GUARDRAILS:UNAUTHORIZED", "Grant Bedrock read access.");
        Method action = AiGridReadinessService.class.getDeclaredMethod("action", gapType);
        action.setAccessible(true);
        Object result = action.invoke(service, gap);
        Method code = result.getClass().getDeclaredMethod("code");
        code.setAccessible(true);
        Method priority = result.getClass().getDeclaredMethod("priority");
        priority.setAccessible(true);

        assertEquals("RESTORE_CONNECTOR_CAPABILITY", code.invoke(result));
        assertEquals(6, priority.invoke(result));
    }
}
