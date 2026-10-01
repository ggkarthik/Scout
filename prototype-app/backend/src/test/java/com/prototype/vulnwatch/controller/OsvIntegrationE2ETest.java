package com.prototype.vulnwatch.controller;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.AuthRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresControllerIntegrationTest
class OsvIntegrationE2ETest {

  private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
      LocalPostgresTestDatabase.provision("osv_controller");

  @DynamicPropertySource
  static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
    PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
  }

  @Autowired
  private MockMvc mvc;

  @Autowired
  private OsvAdvisoryRepository osvRepository;

  @Autowired
  private TenantService tenantService;

  private UUID testTenantId;

  @BeforeEach
  void setUp() {
    testTenantId = tenantService.getDefaultTenant().getId();
    osvRepository.deleteAll();
  }

  private org.springframework.test.web.servlet.ResultActions get(String path, Object... variables) throws Exception {
    return mvc.perform(AuthRequest.asPlatformOwner(AuthRequest.authedGet(path, variables)));
  }

  @Test
  void testGetComponentAdvisories_ReturnsOsvData() throws Exception {
    OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("GHSA-test-1234-5678")
        .ecosystem("npm")
        .packageName("lodash")
        .summary("Test vulnerability")
        .severity("HIGH")
        .cvssV3Score(java.math.BigDecimal.valueOf(7.5))
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .publishedAt(Instant.now())
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(advisory);

    get("/api/tenants/{tenantId}/osv/component-advisories?" +
            "ecosystem=npm&packageName=lodash",
        testTenantId)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", hasSize(1)))
        .andExpect(jsonPath("$[0].osvId").value("GHSA-test-1234-5678"))
        .andExpect(jsonPath("$[0].ecosystem").value("npm"))
        .andExpect(jsonPath("$[0].packageName").value("lodash"))
        .andExpect(jsonPath("$[0].severity").value("HIGH"));
  }

  @Test
  void testGetCoverage_ReturnsEcosystemCounts() throws Exception {
    OsvAdvisoryEntity npm = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-npm-1")
        .ecosystem("npm")
        .packageName("react")
        .summary("npm test")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .syncedAt(Instant.now())
        .build();

    OsvAdvisoryEntity python = OsvAdvisoryEntity.builder()
        .id(UUID.randomUUID())
        .osvId("OSV-python-1")
        .ecosystem("Python")
        .packageName("django")
        .summary("python test")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(npm);
    osvRepository.save(python);

    get("/api/tenants/{tenantId}/osv/coverage", testTenantId)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.ecosystemCounts.npm").value(1))
        .andExpect(jsonPath("$.ecosystemCounts.Python").value(1))
        .andExpect(jsonPath("$.totalAdvisories").value(2));
  }

  @Test
  void testGetComponentAdvisories_NoResults() throws Exception {
    get("/api/tenants/{tenantId}/osv/component-advisories?" +
            "ecosystem=Rust&packageName=nonexistent",
        testTenantId)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", hasSize(0)));
  }

  @Test
  void testGetCoverage_EmptyDatabase() throws Exception {
    get("/api/tenants/{tenantId}/osv/coverage", testTenantId)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.ecosystemCounts").isEmpty())
        .andExpect(jsonPath("$.totalAdvisories").value(0));
  }

  @Test
  void testGetComponentAdvisories_MultipleResults() throws Exception {
    for (int i = 0; i < 3; i++) {
      OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
          .id(UUID.randomUUID())
          .osvId("GHSA-multi-" + i)
          .ecosystem("npm")
          .packageName("lodash")
          .summary("Multiple test " + i)
          .severity("MODERATE")
          .affectedRanges("[]")
          .osvData("{}")
          .source("nvd")
          .syncedAt(Instant.now())
          .build();
      osvRepository.save(advisory);
    }

    get("/api/tenants/{tenantId}/osv/component-advisories?" +
            "ecosystem=npm&packageName=lodash",
        testTenantId)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", hasSize(3)));
  }
}
