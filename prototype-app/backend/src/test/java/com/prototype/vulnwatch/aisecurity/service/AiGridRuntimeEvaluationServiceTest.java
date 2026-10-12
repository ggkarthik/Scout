package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridRuntimeEvaluationServiceTest {
    @Test void doesNotReadHistoricalEvidenceOrReconcileFindings() {
        var jdbc = mock(NamedParameterJdbcTemplate.class);
        var findings = mock(AiGridFindingService.class);
        var snapshots = mock(AiGridSnapshotService.class);
        var capabilities = mock(AiGridCapabilityService.class);
        var service = new AiGridRuntimeEvaluationService(jdbc, new ObjectMapper(), findings, snapshots, capabilities, 14);
        assertEquals(0, service.evaluateRun(new Tenant(), UUID.randomUUID()));
        verifyNoInteractions(jdbc, findings, snapshots, capabilities);
    }
}
