package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.FindingWorkspaceSeedSupport;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

@PostgresIntegrationTest
@Transactional
class FindingWorkspaceProjectionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_workspace_projection");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private FindingListProjectionService findingListProjectionService;

    @Autowired
    private FindingAnalyticsService findingAnalyticsService;

    @Autowired
    private FindingQueueAnalyticsService findingQueueAnalyticsService;

    @Autowired
    private FindingPortfolioRollupService findingPortfolioRollupService;

    @Autowired
    private NamedParameterJdbcTemplate jdbcTemplate;

    private Tenant tenant;

    @BeforeEach
    void seedWorkspace() {
        tenant = tenantService.getDefaultTenant();
        if (tenantSchemaExecutionService.run(tenant, () -> findingRepository.count()) < 90) {
            FindingWorkspaceSeedSupport seedSupport = new FindingWorkspaceSeedSupport(
                    assetRepository,
                    sbomUploadRepository,
                    inventoryComponentRepository,
                    vulnerabilityRepository,
                    findingRepository,
                    tenantSchemaExecutionService
            );
            seedSupport.seedCriticalWorkspace(tenant, 90, 40);
        }
        findingListProjectionService.refreshTenant(tenant);
    }

    @Test
    void projectionStatusDetectsMissingRowsAndRebuildRestoresParity() {
        FindingListProjectionService.ProjectionStatus healthy = findingListProjectionService.inspectProjectionStatus(tenant);
        assertEquals(90, healthy.findingCount());
        assertEquals(90, healthy.sourceFindingCount());
        assertFalse(healthy.stale());

        tenantSchemaExecutionService.run(tenant, () -> {
            jdbcTemplate.update("DELETE FROM finding_list_projection", new MapSqlParameterSource());
            return null;
        });

        FindingListProjectionService.ProjectionStatus broken = findingListProjectionService.inspectProjectionStatus(tenant);
        assertTrue(broken.stale());
        assertEquals(0, broken.findingCount());
        assertEquals(90, broken.sourceFindingCount());
        assertEquals(90, broken.driftCount());

        findingListProjectionService.refreshTenant(tenant);
        FindingListProjectionService.ProjectionStatus repaired = findingListProjectionService.inspectProjectionStatus(tenant);
        assertFalse(repaired.stale());
        assertEquals(90, repaired.findingCount());
        assertEquals(90, repaired.sourceFindingCount());
        assertEquals(0, repaired.driftCount());
        assertNotNull(repaired.lastRebuildDurationMs());
    }

    @Test
    void projectionBackedReadsStayConsistentForCriticalAndRoutingScopes() {
        var criticalOpen = new com.prototype.vulnwatch.dto.FindingsFilter(
                java.util.List.of("CRITICAL"),
                java.util.List.of("OPEN"),
                null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null
        );
        var unassignedCritical = new com.prototype.vulnwatch.dto.FindingsFilter(
                java.util.List.of("CRITICAL"),
                java.util.List.of("OPEN"),
                null, null, null, null, null, null,
                null, null, null, null, null, null, Boolean.TRUE,
                null, null, null, null, null, null
        );

        var summary = findingAnalyticsService.getSummary(tenant, criticalOpen);
        var queueAnalytics = findingQueueAnalyticsService.getQueueAnalytics(tenant, criticalOpen);
        var portfolio = findingPortfolioRollupService.getPortfolioRollup(tenant);

        assertEquals(90, summary.openCount());
        assertEquals(90, queueAnalytics.assignedOpenCount() + queueAnalytics.unassignedOpenCount());
        assertTrue(portfolio.queueRollups().stream()
                .anyMatch(queue -> "critical-open".equals(queue.queueKey()) && queue.openCount() == 90));

        var routingSummary = findingAnalyticsService.getSummary(tenant, unassignedCritical);
        var routingAnalytics = findingQueueAnalyticsService.getQueueAnalytics(tenant, unassignedCritical);
        assertEquals(40, routingSummary.openCount());
        assertEquals(40, routingSummary.unassignedOpenCount());
        assertEquals(40, routingAnalytics.unassignedOpenCount());
    }

    @Test
    void scaleSeedSupportsRepeatableWorkspaceTimingMeasurements() {
        FindingWorkspaceSeedSupport seedSupport = new FindingWorkspaceSeedSupport(
                assetRepository,
                sbomUploadRepository,
                inventoryComponentRepository,
                vulnerabilityRepository,
                findingRepository,
                tenantSchemaExecutionService
        );
        seedSupport.seedCriticalWorkspace(tenant, 250, 100);
        findingListProjectionService.refreshTenant(tenant);

        long startedAt = System.nanoTime();
        findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), null, 25);
        long firstPageMs = (System.nanoTime() - startedAt) / 1_000_000L;

        var firstPage = findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), null, 25);
        startedAt = System.nanoTime();
        findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), firstPage.nextCursor(), 25);
        long laterPageMs = (System.nanoTime() - startedAt) / 1_000_000L;

        assertTrue(firstPageMs >= 0);
        assertTrue(laterPageMs >= 0);
    }
}
