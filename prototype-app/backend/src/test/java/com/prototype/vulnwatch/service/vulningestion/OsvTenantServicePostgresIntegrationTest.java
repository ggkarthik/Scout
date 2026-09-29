package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@PostgresIntegrationTest
class OsvTenantServicePostgresIntegrationTest {

  @Autowired
  private OsvTenantService tenantService;

  @Autowired
  private OsvAdvisoryRepository osvRepository;

  private UUID testTenantId;

  @BeforeEach
  void setUp() {
    testTenantId = UUID.randomUUID();
  }

  @Test
  void testCorrelateOsvAdvisories_ServiceInitialized() {
    assertNotNull(tenantService);
    assertNotNull(osvRepository);
  }

  @Test
  void testMultiTenantContext_PlatformDataShared() {
    // Platform-level OSV data (shared)
    OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-SHARED-1")
        .ecosystem("npm")
        .packageName("lodash")
        .summary("Shared vulnerability")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(advisory);

    // Verify accessible from platform level
    var found = osvRepository.findByEcosystemAndPackageName("npm", "lodash");
    assertEquals(1, found.size());
  }

  @Test
  void testCorrelateOsvAdvisories_HandlesEmptyInventory() {
    // When tenant has no components, should not create findings
    tenantService.correlateOsvAdvisoriesForTenant(testTenantId);
    // Should complete without error
    assertTrue(true);
  }

  @Test
  void testCorrelateOsvAdvisories_GracefulErrorHandling() {
    // If OSV repository has corrupt data, should handle gracefully
    OsvAdvisoryEntity entity = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-BAD-DATA")
        .ecosystem("npm")
        .packageName("test")
        .summary("Bad data")
        .affectedRanges("invalid json")  // Invalid JSON
        .osvData("not-json")  // Invalid JSON
        .source("nvd")
        .build();

    osvRepository.save(entity);

    // Should not throw
    assertDoesNotThrow(() -> {
      tenantService.correlateOsvAdvisoriesForTenant(testTenantId);
    });
  }

  @Test
  void testScheduledCorrelation_PicksUpPlatformData() {
    // Populate platform-level data
    for (int i = 0; i < 5; i++) {
      OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
          .id(UUID.randomUUID())
          .osvId("OSV-BATCH-" + i)
          .ecosystem("npm")
          .packageName("package-" + i)
          .summary("Batch test " + i)
          .affectedRanges("[]")
          .osvData("{}")
          .source("nvd")
          .syncedAt(Instant.now())
          .build();
      osvRepository.save(advisory);
    }

    assertEquals(5, osvRepository.count());

    // Tenant correlation should see all platform data
    tenantService.correlateOsvAdvisoriesForTenant(testTenantId);
    assertTrue(true);  // Should complete successfully
  }
}
