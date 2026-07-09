package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SloMetricsServiceTest {

    private JdbcTemplate jdbcTemplate;
    @Mock
    private TenantService tenantService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private FindingProjectionStatusService findingProjectionStatusService;

    private SloMetricsService service;
    private Tenant tenantA;
    private Tenant tenantB;

    @BeforeEach
    void setUp() {
        tenantA = tenant("Tenant A");
        tenantB = tenant("Tenant B");
        when(tenantService.listTenants()).thenReturn(List.of(tenantA, tenantB));
        when(tenantSchemaExecutionService.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
    }

    @Test
    void evaluateAggregatesTenantLocalMetricsAcrossSchemas() {
        AtomicInteger uploadCountCalls = new AtomicInteger();
        AtomicInteger uploadSuccessCalls = new AtomicInteger();
        AtomicInteger queueDepthCalls = new AtomicInteger();
        AtomicInteger queueStaleCalls = new AtomicInteger();
        AtomicInteger processingDepthCalls = new AtomicInteger();
        AtomicInteger processingAgeCalls = new AtomicInteger();
        AtomicInteger ingestionQueueDepthCalls = new AtomicInteger();
        AtomicInteger ingestionQueueAgeCalls = new AtomicInteger();
        Instant now = Instant.now();

        jdbcTemplate = new JdbcTemplate() {
            @Override
            public <T> T queryForObject(String sql, Class<T> requiredType, Object... args) {
                if (sql.contains("sbom_uploads") && sql.contains("upper(status)")) {
                    return requiredType.cast(uploadSuccessCalls.getAndIncrement() == 0 ? 7L : 3L);
                }
                if (sql.contains("sbom_uploads")) {
                    return requiredType.cast(uploadCountCalls.getAndIncrement() == 0 ? 8L : 4L);
                }
                if (sql.contains("finding_delta_queue")) {
                    if (sql.contains("processing_started_at")) {
                        Instant instant = processingAgeCalls.getAndIncrement() == 0
                                ? now.minusSeconds(700)
                                : now.minusSeconds(120);
                        return requiredType.cast(Timestamp.from(instant));
                    }
                    if (sql.contains("upper(status) = 'PROCESSING'")) {
                        return requiredType.cast(processingDepthCalls.getAndIncrement() == 0 ? 3L : 1L);
                    }
                    if (args == null || args.length == 0) {
                        return requiredType.cast(queueDepthCalls.getAndIncrement() == 0 ? 6L : 5L);
                    }
                    return requiredType.cast(queueStaleCalls.getAndIncrement() == 0 ? 1L : 0L);
                }
                if (sql.contains("ingestion_jobs")) {
                    if (sql.contains("min(visible_at)")) {
                        Instant instant = ingestionQueueAgeCalls.getAndIncrement() == 0
                                ? now.minusSeconds(660)
                                : now.minusSeconds(120);
                        return requiredType.cast(Timestamp.from(instant));
                    }
                    return requiredType.cast(ingestionQueueDepthCalls.getAndIncrement() == 0 ? 20L : 4L);
                }
                return requiredType.cast(0L);
            }
        };
        when(findingProjectionStatusService.inspectProjectionStatus(tenantA))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        now.minusSeconds(3600),
                        5,
                        5,
                        20L,
                        true,
                        0L
                ));
        when(findingProjectionStatusService.inspectProjectionStatus(tenantB))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        now,
                        5,
                        5,
                        20L,
                        false,
                        0L
                ));
        service = new SloMetricsService(jdbcTemplate, tenantService, tenantSchemaExecutionService, findingProjectionStatusService);

        var response = service.evaluate();

        assertFalse(response.overallCompliant());
        assertEquals(8, response.slos().size());
        assertEquals(11.0, response.slos().get(1).current());
        assertEquals(1.0, response.slos().get(2).current());
        assertEquals(1.0, response.slos().get(3).current());
        assertEquals(4.0, response.slos().get(4).current());
        assertTrue(response.slos().get(5).current() >= 690.0);
        assertEquals(24.0, response.slos().get(6).current());
        assertTrue(response.slos().get(7).current() >= 650.0);
        assertTrue(response.slos().get(0).compliant());
        assertFalse(response.slos().get(5).compliant());
        assertFalse(response.slos().get(7).compliant());
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(java.util.UUID.randomUUID());
        tenant.setName(name);
        tenant.setSchemaName("tenant_" + name.toLowerCase().replace(" ", "_"));
        return tenant;
    }
}
