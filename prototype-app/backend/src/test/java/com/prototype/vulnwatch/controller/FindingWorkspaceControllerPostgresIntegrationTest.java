package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.FindingWorkspaceSeedSupport;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@PostgresControllerIntegrationTest
class FindingWorkspaceControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_workspace_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TenantService tenantService;

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
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    private Tenant tenant;

    @BeforeEach
    void seedWorkspace() {
        tenant = tenantService.getDefaultTenant();
        ensureSeededWorkspace();
    }

    @Test
    void cursorPaginationIsStableAcrossMultiplePages() throws Exception {
        ensureSeededWorkspace();
        findingListProjectionService.refreshTenant(tenant);

        Set<String> ids = new HashSet<>();
        String cursor = null;
        double previousRiskScore = Double.POSITIVE_INFINITY;
        int collected = 0;

        for (int page = 0; page < 4; page++) {
            String url = cursor == null
                    ? "/api/findings?queueKey=critical-open&limit=25"
                    : "/api/findings?queueKey=critical-open&limit=25&cursor=" + cursor;
            MvcResult result = mockMvc.perform(authedGet(url))
                    .andExpect(status().isOk())
                    .andReturn();

            JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
            JsonNode items = body.get("items");
            assertTrue(items.isArray());
            for (JsonNode item : items) {
                String id = item.get("id").asText();
                assertTrue(ids.add(id), "duplicate finding id encountered across cursor pages: " + id);
                double riskScore = item.get("riskScore").asDouble();
                assertTrue(riskScore <= previousRiskScore, "cursor pages must preserve descending risk ordering");
                previousRiskScore = riskScore;
                collected += 1;
            }

            cursor = body.path("nextCursor").isNull() ? null : body.path("nextCursor").asText(null);
        }

        assertEquals(90, collected);

        mockMvc.perform(authedGet("/api/findings?page=0&size=10&queueKey=critical-open"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(90))
                .andExpect(jsonPath("$.size").value(10));
    }

    @Test
    void queueAnalyticsAndRollupsStayParityConsistentForRoutingQueue() throws Exception {
        ensureSeededWorkspace();
        findingListProjectionService.refreshTenant(tenant);

        mockMvc.perform(authedGet("/api/findings?queueKey=unassigned-critical&limit=50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(40));

        mockMvc.perform(authedGet("/api/findings/summary?queueKey=unassigned-critical"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").value(40))
                .andExpect(jsonPath("$.criticalOpenCount").value(40))
                .andExpect(jsonPath("$.unassignedOpenCount").value(40));

        mockMvc.perform(authedGet("/api/findings/queue-analytics?queueKey=unassigned-critical"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignedOpenCount").value(0))
                .andExpect(jsonPath("$.unassignedOpenCount").value(40));

        MvcResult portfolioResult = mockMvc.perform(authedGet("/api/findings/portfolio-rollups"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode rollups = objectMapper.readTree(portfolioResult.getResponse().getContentAsString()).path("queueRollups");
        boolean matched = false;
        for (JsonNode rollup : rollups) {
            if ("unassigned-critical".equals(rollup.path("queueKey").asText())) {
                assertEquals(40, rollup.path("openCount").asInt());
                matched = true;
            }
        }
        assertTrue(matched, "expected unassigned-critical rollup to be present");
    }

    @Test
    void projectionStatusAndRebuildEndpointsExposeFreshnessState() throws Exception {
        ensureSeededWorkspace();
        findingListProjectionService.refreshTenant(tenant);

        mockMvc.perform(asPlatformOwner(authedGet("/api/findings/projection-status")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(90))
                .andExpect(jsonPath("$.sourceFindingCount").value(90))
                .andExpect(jsonPath("$.stale").value(false));

        mockMvc.perform(asPlatformOwner(authedPost("/api/findings/projection-rebuild")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(90))
                .andExpect(jsonPath("$.stale").value(false));
    }

    private void ensureSeededWorkspace() {
        long currentCount = tenantSchemaExecutionService.run(tenant, () -> findingRepository.count());
        if (currentCount >= 90) {
            return;
        }
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
}
