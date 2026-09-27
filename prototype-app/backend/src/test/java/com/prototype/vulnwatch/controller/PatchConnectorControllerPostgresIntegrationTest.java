package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.AuthRequest;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.*;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@PostgresControllerIntegrationTest
class PatchConnectorControllerPostgresIntegrationTest {

    private LocalPostgresTestDatabase testDb;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private FixRepository fixRepository;

    @Autowired
    private AssetFixStatusRepository assetFixStatusRepository;

    @Autowired
    private AssetRepository assetRepository;

    @BeforeEach
    void setUp() {
        testDb = LocalPostgresTestDatabase.provision("patch_controller_test");
    }

    @Test
    void testListConnectors() throws Exception {
        AuthRequest.authedGet(mockMvc, "/api/connectors/patches")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(3))
            .andExpect(jsonPath("$[0].connectorType").exists())
            .andExpect(jsonPath("$[0].name").exists())
            .andExpect(jsonPath("$[0].enabled").value(true));
    }

    @Test
    void testTestConnectionFailsWithBadCredentials() throws Exception {
        Map<String, String> badCreds = Map.of(
            "base_url", "http://invalid.local",
            "database_name", "nonexistent"
        );

        AuthRequest.authedPost(mockMvc, "/api/connectors/SCCM/test", badCreds)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value("error"));
    }

    @Test
    void testTriggerSyncReturnsAccepted() throws Exception {
        AuthRequest.authedPost(mockMvc, "/api/connectors/SCCM/sync", new HashMap<>())
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.status").value("queued"));
    }

    @Test
    void testGetSyncHistory() throws Exception {
        AuthRequest.authedGet(mockMvc, "/api/connectors/SCCM/sync-history?limit=5")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(0));  // No syncs yet
    }

    @Test
    void testGetCoverageMetrics() throws Exception {
        // Setup: Create patches and deployment statuses
        Tenant tenant = tenantService.createTenant("coverage_test", "Coverage Test");

        // Create test data
        Fix patch = Fix.builder()
            .externalId("KB-TEST-001")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Test Patch")
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .effort(Fix.EffortLevel.MEDIUM)
            .status(Fix.FixStatus.ACTIVE)
            .build();
        fixRepository.save(patch);

        Asset asset = Asset.builder()
            .name("test-asset")
            .assetType("Computer")
            .build();
        assetRepository.save(asset);

        AssetFixStatus deployed = AssetFixStatus.builder()
            .tenantId(tenant.getId())
            .asset(asset)
            .fixId(patch.getId())
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();
        assetFixStatusRepository.save(deployed);

        AuthRequest.authedGet(mockMvc, "/api/connectors/patches/coverage/metrics")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalPatches").value(1))
            .andExpect(jsonPath("$.deployedPatches").value(1))
            .andExpect(jsonPath("$.deploymentPercentage").value(100.0));
    }

    @Test
    void testGetFixDeploymentStatus() throws Exception {
        // Setup
        Tenant tenant = tenantService.createTenant("drill_down_test", "Drill Down Test");

        Fix patch = Fix.builder()
            .externalId("KB-DRILL-001")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Drill Down Patch")
            .ecosystem("Windows")
            .severity(Fix.Severity.CRITICAL)
            .effort(Fix.EffortLevel.LOW)
            .status(Fix.FixStatus.ACTIVE)
            .build();
        fixRepository.save(patch);

        Asset asset1 = Asset.builder().name("Server-1").assetType("Computer").build();
        Asset asset2 = Asset.builder().name("Server-2").assetType("Computer").build();
        assetRepository.saveAll(List.of(asset1, asset2));

        AssetFixStatus status1 = AssetFixStatus.builder()
            .tenantId(tenant.getId())
            .asset(asset1)
            .fixId(patch.getId())
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();
        AssetFixStatus status2 = AssetFixStatus.builder()
            .tenantId(tenant.getId())
            .asset(asset2)
            .fixId(patch.getId())
            .deploymentStatus(AssetFixStatus.DeploymentStatus.PENDING)
            .sourceSystem("SCCM")
            .build();
        assetFixStatusRepository.saveAll(List.of(status1, status2));

        AuthRequest.authedGet(mockMvc, "/api/connectors/patches/" + patch.getId() + "/deployment-status")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[0].assetName").exists());
    }

    @Test
    void testCoverageMetricsMultiTenant() throws Exception {
        // Create two tenants
        Tenant tenant1 = tenantService.createTenant("mt_test_1", "Multi-Tenant Test 1");
        Tenant tenant2 = tenantService.createTenant("mt_test_2", "Multi-Tenant Test 2");

        // Create patches
        Fix patch1 = Fix.builder()
            .externalId("KB-MT-001")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("MT Patch 1")
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .status(Fix.FixStatus.ACTIVE)
            .build();
        fixRepository.save(patch1);

        Asset asset1 = Asset.builder().name("MT-Asset-1").assetType("Computer").build();
        assetRepository.save(asset1);

        AssetFixStatus t1Status = AssetFixStatus.builder()
            .tenantId(tenant1.getId())
            .asset(asset1)
            .fixId(patch1.getId())
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();
        assetFixStatusRepository.save(t1Status);

        // Query as tenant1 should see the patch
        AuthRequest.authedGet(mockMvc, "/api/connectors/patches/coverage/metrics")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalPatches").value(1));
    }

    @Test
    void testDashboardOverview() throws Exception {
        AuthRequest.authedGet(mockMvc, "/api/patches/dashboard/overview")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.coverage_metrics").exists())
            .andExpect(jsonPath("$.auto_resolution_stats").exists())
            .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void testDashboardHealth() throws Exception {
        AuthRequest.authedGet(mockMvc, "/api/patches/dashboard/health")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.health_status").exists())
            .andExpect(jsonPath("$.deployment_percentage").exists())
            .andExpect(jsonPath("$.recommendation").exists());
    }

    @Test
    void testHealthStatusExcellent() throws Exception {
        // Setup: Create 100% deployed patches
        Tenant tenant = tenantService.createTenant("health_excellent", "Health Excellent");

        for (int i = 0; i < 10; i++) {
            Fix patch = Fix.builder()
                .externalId("KB-HEALTH-" + i)
                .sourceSystem("SCCM")
                .fixType(Fix.FixType.PATCH)
                .title("Health Patch " + i)
                .ecosystem("Windows")
                .severity(Fix.Severity.HIGH)
                .status(Fix.FixStatus.ACTIVE)
                .build();
            fixRepository.save(patch);

            Asset asset = Asset.builder()
                .name("health-asset-" + i)
                .assetType("Computer")
                .build();
            assetRepository.save(asset);

            AssetFixStatus status = AssetFixStatus.builder()
                .tenantId(tenant.getId())
                .asset(asset)
                .fixId(patch.getId())
                .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
                .sourceSystem("SCCM")
                .build();
            assetFixStatusRepository.save(status);
        }

        AuthRequest.authedGet(mockMvc, "/api/patches/dashboard/health")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.health_status").value("EXCELLENT"))
            .andExpect(jsonPath("$.deployment_percentage").value(100.0));
    }
}
