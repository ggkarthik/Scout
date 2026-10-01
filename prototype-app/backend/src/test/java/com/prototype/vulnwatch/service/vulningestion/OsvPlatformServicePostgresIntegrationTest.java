package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.AdvisoryEquivalenceEntity;
import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.AdvisoryEquivalenceRepository;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@PostgresIntegrationTest
class OsvPlatformServicePostgresIntegrationTest {

  @Autowired
  private OsvPlatformService service;

  @Autowired
  private OsvAdvisoryRepository osvRepository;

  @Autowired
  private AdvisoryEquivalenceRepository equivalenceRepository;

  @Test
  void testMigration_TablesCreated() {
    assertNotNull(osvRepository);
    assertNotNull(equivalenceRepository);

    // Tables should be empty initially
    assertEquals(0, osvRepository.count());
    assertEquals(0, equivalenceRepository.count());
  }

  @Test
  void testSaveOsvAdvisory_PersistsToDatabase() {
    OsvAdvisoryEntity entity = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-2021-1234")
        .ecosystem("npm")
        .packageName("lodash")
        .summary("Command Injection in lodash")
        .severity("HIGH")
        .affectedRanges("[{\"type\":\"SEMVER\"}]")
        .osvData("{\"id\":\"OSV-2021-1234\",\"summary\":\"test\"}")
        .source("nvd")
        .publishedAt(Instant.now())
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(entity);

    List<OsvAdvisoryEntity> saved = osvRepository.findByEcosystemAndPackageName("npm", "lodash");
    assertEquals(1, saved.size());
    assertEquals("OSV-2021-1234", saved.get(0).getOsvId());
  }

  @Test
  void testBuildEquivalenceMappings_CreatesRecords() {
    OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-2021-5678")
        .ecosystem("Python")
        .packageName("django")
        .summary("Django vulnerability")
        .affectedRanges("[]")
        .osvData("{\"id\":\"OSV-2021-5678\"}")
        .source("nvd")
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(advisory);

    AdvisoryEquivalenceEntity eq = AdvisoryEquivalenceEntity.builder()
        .id(UUID.randomUUID())
        .nvdCveId("CVE-2021-12345")
        .ghsaId("GHSA-xxxx-yyyy-zzzz")
        .osvId("OSV-2021-5678")
        .equivalenceConfidence(java.math.BigDecimal.valueOf(0.95))
        .equivalenceReason("same_advisory")
        .discoveredAt(Instant.now())
        .build();

    equivalenceRepository.save(eq);

    List<AdvisoryEquivalenceEntity> found = equivalenceRepository.findByNvdCveId("CVE-2021-12345");
    assertEquals(1, found.size());
    assertEquals("GHSA-xxxx-yyyy-zzzz", found.get(0).getGhsaId());
  }

  @Test
  void testUniqueConstraint_OsvIdUnique() {
    OsvAdvisoryEntity entity1 = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-UNIQUE-1")
        .ecosystem("npm")
        .packageName("test1")
        .summary("Test 1")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .build();

    OsvAdvisoryEntity entity2 = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-UNIQUE-1")  // Same OSV ID
        .ecosystem("npm")
        .packageName("test2")
        .summary("Test 2")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .build();

    osvRepository.save(entity1);

    assertThrows(Exception.class, () -> {
      osvRepository.save(entity2);
    });
  }

  @Test
  void testEquivalenceIndexes_QueryPerformance() {
    for (int i = 0; i < 10; i++) {
      AdvisoryEquivalenceEntity eq = AdvisoryEquivalenceEntity.builder()
          .id(UUID.randomUUID())
          .nvdCveId("CVE-2021-" + i)
          .ghsaId("GHSA-" + i)
          .osvId("OSV-" + i)
          .equivalenceReason("same_cve")
          .discoveredAt(Instant.now())
          .build();
      equivalenceRepository.save(eq);
    }

    long startTime = System.nanoTime();
    equivalenceRepository.findByNvdCveId("CVE-2021-5");
    long endTime = System.nanoTime();

    long durationMs = (endTime - startTime) / 1_000_000;
    assertTrue(durationMs < 100, "Query should complete in < 100ms with indexes");
  }
}
