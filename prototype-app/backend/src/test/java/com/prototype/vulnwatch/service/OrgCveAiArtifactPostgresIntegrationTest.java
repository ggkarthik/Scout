package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.repo.OrgCveAiArtifactRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class OrgCveAiArtifactPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("org_cve_ai_artifact");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @Autowired
    private OrgCveAiArtifactRepository orgCveAiArtifactRepository;

    @Autowired
    private CveAiSolutionPersistenceService aiSolutionPersistenceService;

    @Autowired
    private CveInvestigationSummaryPersistenceService summaryPersistenceService;

    @Autowired
    private EntityManager entityManager;

    @Test
    void persistsAiArtifactsSeparatelyAndDeletesThemWithOrgCveRecord() {
        ensureDefaultTenant();
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        try {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2099-3001");
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("AI artifact persistence");
        vulnerability.setSeverity("HIGH");
        vulnerability.setLastModifiedAt(Instant.now());
        vulnerability = vulnerabilityRepository.save(vulnerability);

        OrgCveRecord record = new OrgCveRecord();
        record.setTenant(tenant);
        record.setVulnerability(vulnerability);
        record.setExternalId(vulnerability.getExternalId());
        record = orgCveRecordRepository.saveAndFlush(record);

        aiSolutionPersistenceService.saveAiSolution(vulnerability.getExternalId(), "{\"solution\":\"rotate secret\"}");
        aiSolutionPersistenceService.saveAiActions(vulnerability.getExternalId(), "{\"actions\":[\"patch\",\"verify\"]}");
        summaryPersistenceService.saveSummary(
                vulnerability.getExternalId(),
                Map.of("component", "nginx"),
                sampleSummary(),
                "ai"
        );

        entityManager.clear();

        SavedCveInvestigationSummaryResponse savedSummary =
                summaryPersistenceService.getSavedSummary(vulnerability.getExternalId());
        var savedSolution = aiSolutionPersistenceService.getSavedAiSolution(vulnerability.getExternalId()).orElseThrow();
        var savedActions = aiSolutionPersistenceService.getSavedAiActions(vulnerability.getExternalId()).orElseThrow();

        assertEquals("ai", savedSummary.mode());
        assertTrue(savedSolution.contentJson().contains("rotate secret"));
        assertTrue(savedActions.contentJson().contains("\"patch\""));
        assertTrue(orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId()).isPresent());

        OrgCveRecord persistedRecord = orgCveRecordRepository.findById(record.getId()).orElseThrow();
        orgCveRecordRepository.delete(persistedRecord);
        orgCveRecordRepository.flush();
        entityManager.clear();

        assertFalse(orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId()).isPresent());
        } finally {
            TenantContext.clear();
        }
    }

    private CveInvestigationSummaryResponse sampleSummary() {
        return new CveInvestigationSummaryResponse(
                Instant.now(),
                "Executive summary",
                new CveInvestigationSummaryResponse.RiskAnalysis("HIGH", 85, "Internet-exposed workload"),
                new CveInvestigationSummaryResponse.ImpactAnalysis(1, 3, "None", "No EOL exposure", "Patch missing"),
                List.of(new CveInvestigationSummaryResponse.RemediationAction(
                        1,
                        "P1",
                        "Patch nginx",
                        "Upgrade to vendor-fixed build",
                        "Platform",
                        "24h",
                        "PATCH"
                )),
                List.of("External attack path"),
                new CveInvestigationSummaryResponse.MetricsSummary(3, 3, 0, 1, 3, 0),
                "# Report"
        );
    }

    private void ensureDefaultTenant() {
        tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(TenantService.DEFAULT_TENANT_NAME);
            return tenantRepository.save(tenant);
        });
    }
}
