package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiAgentExecutionRetentionServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void drainsBoundedParentBatchesAndReportsRemainingEligibleRows() {
        TenantService tenants = mock(TenantService.class);
        TenantSchemaExecutionService execution = mock(TenantSchemaExecutionService.class);
        NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
        when(execution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
        when(jdbc.update(contains("limit :batchSize"), any(SqlParameterSource.class))).thenReturn(250, 0);
        when(jdbc.queryForObject(contains("select count(*)"), any(SqlParameterSource.class),
                org.mockito.ArgumentMatchers.eq(Long.class))).thenReturn(0L);
        AiAgentExecutionRetentionService service = new AiAgentExecutionRetentionService(
                tenants, execution, jdbc, 90, 250);
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        var result = service.purge(tenant);

        assertEquals(250, result.deleted());
        assertEquals(0, result.remainingEligible());
        assertEquals(2, result.batches());
        verify(jdbc, times(2)).update(contains("delete from ai_agent_executions"), any(SqlParameterSource.class));
    }
}
