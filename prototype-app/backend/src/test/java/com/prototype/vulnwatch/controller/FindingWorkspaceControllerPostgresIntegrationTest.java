package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static com.prototype.vulnwatch.support.AuthRequest.withTenant;
import static com.prototype.vulnwatch.support.AuthRequest.withUser;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantSupportGrantRepository;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private TenantSupportGrantRepository tenantSupportGrantRepository;

    private Tenant tenant;
    private FindingWorkspaceSeedSupport.SeededWorkspace seedWorkspace;

    @BeforeEach
    void seedWorkspace() {
        tenant = tenantService.getDefaultTenant();
        ensureSeededWorkspace();
    }

    @Test
    void cursorPaginationSupportsNamedFiltersWithoutBreakingSqlParameterParsing() throws Exception {
        ensureSeededWorkspace();
        findingListProjectionService.refreshTenant(tenant);

        mockMvc.perform(authedGet("/api/findings?queueKey=critical-open&vulnerabilityId="
                        + seedWorkspace.vulnerabilityId()
                        + "&limit=25"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(90))
                .andExpect(jsonPath("$.items.length()").value(25));
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
    void listAndSummaryStayParityConsistentForRoutingQueue() throws Exception {
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
    }

    @Test
    void projectionStatusAndRebuildEndpointsExposeFreshnessState() throws Exception {
        ensureSeededWorkspace();
        findingListProjectionService.refreshTenant(tenant);
        ensurePlatformOwnerWriteGrant();

        mockMvc.perform(withTenant(
                        withUser(asPlatformOwner(authedGet("/api/findings/projection-status")),
                                PostgresITSupport.DEFAULT_USER_ID),
                        tenant.getId().toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(90))
                .andExpect(jsonPath("$.sourceFindingCount").value(90))
                .andExpect(jsonPath("$.stale").value(false));

        mockMvc.perform(withTenant(
                        withUser(asPlatformOwner(authedPost("/api/findings/projection-rebuild")),
                                PostgresITSupport.DEFAULT_USER_ID),
                        tenant.getId().toString()))
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
        seedWorkspace = seedSupport.seedCriticalWorkspace(tenant, 90, 40);
    }

    private void ensurePlatformOwnerWriteGrant() {
        AppUser owner = appUserRepository.findByExternalSubject(PostgresITSupport.DEFAULT_USER_ID)
                .orElseGet(() -> {
                    AppUser user = new AppUser();
                    user.setExternalSubject(PostgresITSupport.DEFAULT_USER_ID);
                    user.setEmail("platform-owner@example.test");
                    user.setDisplayName("Test platform owner");
                    user.setPlatformOwner(true);
                    user.setStatus("ACTIVE");
                    return appUserRepository.save(user);
                });
        if (!tenantSupportGrantRepository.findActiveByInvitedPlatformSubjectAndTenantId(
                owner.getExternalSubject(), tenant.getId(), Instant.now()).isEmpty()) {
            return;
        }
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setInvitedPlatformSubject(owner.getExternalSubject());
        grant.setReason("Finding projection integration test");
        grant.setScope("Projection rebuild");
        grant.setAccessMode("WRITE_ENABLED");
        grant.setStatus("ACTIVE");
        grant.setGrantedBy(owner);
        grant.setAcceptedBy(owner);
        grant.setRequestedAt(Instant.now());
        grant.setAcceptedAt(Instant.now());
        grant.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
        grant.setUpdatedAt(Instant.now());
        tenantSupportGrantRepository.save(grant);
    }
}
