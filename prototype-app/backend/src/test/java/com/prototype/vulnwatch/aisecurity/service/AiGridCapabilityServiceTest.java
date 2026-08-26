package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridCapabilityServiceTest {
    private final NamedParameterJdbcTemplate jdbc = org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class);
    private final TenantSchemaExecutionService tenantExecution = org.mockito.Mockito.mock(TenantSchemaExecutionService.class);
    private final AiGridCapabilityService service = new AiGridCapabilityService(jdbc, tenantExecution);

    @BeforeEach
    void executeTenantSuppliers() {
        org.mockito.Mockito.doAnswer(invocation -> ((java.util.function.Supplier<?>) invocation.getArgument(1)).get())
                .when(tenantExecution).run(org.mockito.ArgumentMatchers.any(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<?>>any());
    }

    @Test
    void incompleteAndExpiredCapabilitiesAreExplicitNoDecisionGaps() {
        Instant now = Instant.now();
        var partial = new AiGridCapabilityService.CapabilityKey("AWS", "BEDROCK_AGENTS", "123", "us-east-1");
        var stale = new AiGridCapabilityService.CapabilityKey("AWS", "IAM_ROLE_POLICIES", "123", "us-east-1");
        assertEquals(java.util.List.of("capability:BEDROCK_AGENTS:PARTIAL", "capability:IAM_ROLE_POLICIES:STALE"),
                service.gaps(Map.of(partial, new AiGridCapabilityService.CapabilityState("PARTIAL", now, now.plusSeconds(60)),
                                stale, new AiGridCapabilityService.CapabilityState("COMPLETE", now.minusSeconds(7200), now.minusSeconds(1))),
                        "AWS", "123", "us-east-1", java.util.List.of("BEDROCK_AGENTS", "IAM_ROLE_POLICIES")));
    }

    @Test
    void latestCapabilitiesRunWithinTheRequestedTenantContext() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        org.mockito.Mockito.when(jdbc.query(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.RowMapper.class)))
                .thenReturn(java.util.List.of());

        assertEquals(java.util.List.of(), service.latest(tenant));

        org.mockito.Mockito.verify(tenantExecution).run(org.mockito.ArgumentMatchers.same(tenant),
                org.mockito.ArgumentMatchers.<java.util.function.Supplier<?>>any());
    }
}
