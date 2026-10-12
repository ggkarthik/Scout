package com.prototype.vulnwatch.aisecurity.service;

import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridRuntimeIngestionWorkerTest {
    @Test void evenAnEnabledWorkerDoesNotClaimQueuedBatches() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        TenantService tenants = mock(TenantService.class);
        AiAgentExecutionIngestionService ingestion = mock(AiAgentExecutionIngestionService.class);
        var worker = new AiGridRuntimeIngestionWorker(jobs, tenants, mock(TenantSchemaExecutionService.class),
                mock(NamedParameterJdbcTemplate.class), ingestion, new ObjectMapper(), true);
        worker.poll();
        verifyNoInteractions(jobs, tenants, ingestion);
    }
}
