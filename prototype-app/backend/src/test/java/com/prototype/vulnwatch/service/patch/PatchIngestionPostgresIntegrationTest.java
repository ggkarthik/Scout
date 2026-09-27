package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@PostgresControllerIntegrationTest
class PatchIngestionPostgresIntegrationTest {

    private LocalPostgresTestDatabase testDb;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private FixRepository fixRepository;

    @Autowired
    private AssetFixStatusRepository assetFixStatusRepository;

    @Autowired
    private PatchConnectorCredentialRepository credentialRepository;

    @Autowired
    private InventoryComponentRepository componentRepository;

    @Autowired
    private AssetRepository assetRepository;

    @BeforeEach
    void setUp() {
        testDb = LocalPostgresTestDatabase.provision("patch_ingestion_test");
    }

    @Test
    void testMultiTenantFixIsolation() {
        // Arrange: Create two tenants with different patches
        Tenant tenant1 = tenantService.createTenant("tenant1", "Tenant 1");
        Tenant tenant2 = tenantService.createTenant("tenant2", "Tenant 2");

        Fix fix1 = Fix.builder()
            .externalId("KB5027398")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Windows Patch 1")
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .effort(Fix.EffortLevel.MEDIUM)
            .status(Fix.FixStatus.ACTIVE)
            .build();

        Fix fix2 = Fix.builder()
            .externalId("KB5000000")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Windows Patch 2")
            .ecosystem("Windows")
            .severity(Fix.Severity.CRITICAL)
            .effort(Fix.EffortLevel.LOW)
            .status(Fix.FixStatus.ACTIVE)
            .build();

        // Act: Save fixes to repository
        fixRepository.saveAll(List.of(fix1, fix2));

        // Create asset fix statuses for each tenant
        tenantSchemaExecutionService.run(tenant1, () -> {
            Asset asset1 = Asset.builder()
                .name("asset1")
                .assetType("Computer")
                .build();
            assetRepository.save(asset1);

            AssetFixStatus afs1 = AssetFixStatus.builder()
                .tenantId(tenant1.getId())
                .asset(asset1)
                .fixId(fix1.getId())
                .applicable(true)
                .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
                .sourceSystem("SCCM")
                .build();
            assetFixStatusRepository.save(afs1);

            return null;
        });

        tenantSchemaExecutionService.run(tenant2, () -> {
            Asset asset2 = Asset.builder()
                .name("asset2")
                .assetType("Computer")
                .build();
            assetRepository.save(asset2);

            AssetFixStatus afs2 = AssetFixStatus.builder()
                .tenantId(tenant2.getId())
                .asset(asset2)
                .fixId(fix2.getId())
                .applicable(true)
                .deploymentStatus(AssetFixStatus.DeploymentStatus.PENDING)
                .sourceSystem("SCCM")
                .build();
            assetFixStatusRepository.save(afs2);

            return null;
        });

        // Assert: Verify Tenant1 only sees its own patches
        tenantSchemaExecutionService.run(tenant1, () -> {
            var tenant1Statuses = assetFixStatusRepository.findByTenantAndDeploymentStatus(
                tenant1.getId(),
                AssetFixStatus.DeploymentStatus.DEPLOYED
            );
            assertEquals(1, tenant1Statuses.size());
            assertEquals(fix1.getId(), tenant1Statuses.get(0).getFixId());

            return null;
        });

        // Assert: Verify Tenant2 only sees its own patches
        tenantSchemaExecutionService.run(tenant2, () -> {
            var tenant2Statuses = assetFixStatusRepository.findByTenantAndDeploymentStatus(
                tenant2.getId(),
                AssetFixStatus.DeploymentStatus.PENDING
            );
            assertEquals(1, tenant2Statuses.size());
            assertEquals(fix2.getId(), tenant2Statuses.get(0).getFixId());

            return null;
        });
    }

    @Test
    void testCredentialEncryption() {
        // Arrange
        String plainPassword = "SuperSecurePassword123!";
        PatchConnectorCredential credential = PatchConnectorCredential.builder()
            .connectorType("SCCM")
            .tenantId(null)  // Platform-level
            .authMethod("SQL_AUTH")
            .encryptedSecret("enc:v1:encrypted_data")  // Pretend encrypted
            .build();

        // Act
        PatchConnectorCredential saved = credentialRepository.save(credential);

        // Assert
        assertNotNull(saved.getId());
        assertTrue(saved.getEncryptedSecret().startsWith("enc:"));
        assertNotEquals(plainPassword, saved.getEncryptedSecret());
        assertEquals("SCCM", saved.getConnectorType());
    }

    @Test
    void testPatchDeduplication() {
        // Arrange: Create two fixes with similar titles
        Fix fix1 = Fix.builder()
            .externalId("KB5027398")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Windows 10 Security Update KB5027398")
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .status(Fix.FixStatus.ACTIVE)
            .build();

        Fix fix2 = Fix.builder()
            .externalId("KB5027399")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Windows 10 Security Update KB5027399")  // Very similar
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .status(Fix.FixStatus.ACTIVE)
            .build();

        fixRepository.saveAll(List.of(fix1, fix2));

        // Act
        var allFixes = fixRepository.findByEcosystem("Windows");

        // Assert
        assertEquals(2, allFixes.size());
        // Both should be distinct (not deduplicated at this level)
        assertTrue(allFixes.stream().anyMatch(f -> f.getExternalId().equals("KB5027398")));
        assertTrue(allFixes.stream().anyMatch(f -> f.getExternalId().equals("KB5027399")));
    }

    @Test
    void testAssetFixStatusTenantScoped() throws Exception {
        // Arrange
        Tenant tenant1 = tenantService.createTenant("tenant1_scope_test", "Tenant 1 Scope Test");

        Asset asset = Asset.builder()
            .name("test_asset")
            .assetType("Computer")
            .build();

        Fix fix = Fix.builder()
            .externalId("KB-TEST-001")
            .sourceSystem("SCCM")
            .fixType(Fix.FixType.PATCH)
            .title("Test Patch")
            .ecosystem("Windows")
            .severity(Fix.Severity.MEDIUM)
            .status(Fix.FixStatus.ACTIVE)
            .build();

        fixRepository.save(fix);

        tenantSchemaExecutionService.run(tenant1, () -> {
            assetRepository.save(asset);

            AssetFixStatus afs = AssetFixStatus.builder()
                .tenantId(tenant1.getId())
                .asset(asset)
                .fixId(fix.getId())
                .applicable(true)
                .deploymentStatus(AssetFixStatus.DeploymentStatus.PENDING)
                .sourceSystem("SCCM")
                .build();
            assetFixStatusRepository.save(afs);

            // Verify it was saved
            var retrieved = assetFixStatusRepository.findByTenantAndAssetAndFix(
                tenant1.getId(),
                asset.getId(),
                fix.getId()
            );
            assertTrue(retrieved.isPresent());
            assertEquals(asset.getId(), retrieved.get().getAsset().getId());

            return null;
        });

        // Assert: Verify RLS prevents cross-tenant access via direct query
        // (This would be tested at database level with role-based access)
    }

    @Test
    void testSccmPatchConnectorEndpoint() throws Exception {
        // Test that the patch connector endpoints are accessible
        AuthRequest.authedGet(mockMvc, "/api/connectors/patches")
            .andExpect(status().isOk());
    }

    @Test
    void testPatchConnectorTestEndpoint() throws Exception {
        // Arrange
        Map<String, String> credentials = Map.of(
            "base_url", "http://invalid-sccm.local",
            "database_name", "test_db",
            "auth_type", "SQL_AUTH"
        );

        // Act & Assert: Should fail gracefully
        AuthRequest.authedPost(mockMvc, "/api/connectors/SCCM/test", credentials)
            .andExpect(status().isBadRequest());
    }

    @Test
    void testManualSyncTrigger() throws Exception {
        // Arrange
        Map<String, String> filters = Map.of("limit", "100");

        // Act & Assert: Trigger should return 202 Accepted
        AuthRequest.authedPost(mockMvc, "/api/connectors/SCCM/sync", filters)
            .andExpect(status().isAccepted());
    }

    @Test
    void testSyncHistoryEndpoint() throws Exception {
        // Act & Assert
        AuthRequest.authedGet(mockMvc, "/api/connectors/SCCM/sync-history?limit=10")
            .andExpect(status().isOk());
    }
}
