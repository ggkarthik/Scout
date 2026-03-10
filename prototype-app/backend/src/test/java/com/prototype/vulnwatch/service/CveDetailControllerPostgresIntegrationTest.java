package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.repo.ApplicabilityAssessmentRepository;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.InvestigationRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CveDetailControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cve_detail_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private InvestigationRepository investigationRepository;

    @Autowired
    private ApplicabilityAssessmentRepository assessmentRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @Test
    void submitEndpointsUseRealTenantAndPersistWorkflowOnPostgres() throws Exception {
        String cveId = "CVE-2099-9902";
        createVulnerability(cveId);

        mockMvc.perform(post("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "priority": "HIGH",
                                  "assignedTo": "analyst-a",
                                  "notes": "triage started"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.priority").value("HIGH"));

        mockMvc.perform(post("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "priority": "MEDIUM",
                                  "assignedTo": "analyst-b",
                                  "notes": "handoff"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.priority").value("MEDIUM"));

        mockMvc.perform(post("/api/cve-detail/{cveId}/assessment/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "softwareDetected": true,
                                  "detectionMethod": "sbom",
                                  "affectedComponents": "pkg:maven/example/component",
                                  "vulnerableVersionPresent": true,
                                  "finalResult": "AFFECTED",
                                  "confidenceLevel": "HIGH",
                                  "justification": "validated via inventory",
                                  "recommendedAction": "patch immediately"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.finalResult").value("AFFECTED"));

        mockMvc.perform(get("/api/cve-detail/{cveId}", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.externalId").value(cveId))
                .andExpect(jsonPath("$.investigations[0].status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.assessments[0].status").value("COMPLETED"));

        Tenant tenant = tenantService.getDefaultTenant();
        Investigation investigation = investigationRepository.findByTenantIdAndCveId(tenant.getId(), cveId).stream()
                .findFirst()
                .orElseThrow();
        ApplicabilityAssessment assessment = assessmentRepository.findByTenantIdAndCveId(tenant.getId(), cveId).stream()
                .findFirst()
                .orElseThrow();

        assertEquals(Investigation.InvestigationStatus.IN_PROGRESS, investigation.getStatus());
        assertEquals(ApplicabilityAssessment.AssessmentStatus.COMPLETED, assessment.getStatus());
    }

    @Test
    void suppressEndpointPersistsOrgCveSuppressionAndSuppressesExistingFindings() throws Exception {
        String cveId = "CVE-2099-9903";
        Vulnerability vulnerability = createVulnerability(cveId);
        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "suppression-check");
        createOpenFinding(tenant, component, vulnerability);

        mockMvc.perform(post("/api/cve-detail/{cveId}/suppress", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "FALSE_POSITIVE",
                                  "justification": "validated compensating control",
                                  "duration": 30
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.suppressed").value(true))
                .andExpect(jsonPath("$.reason").value("FALSE_POSITIVE"))
                .andExpect(jsonPath("$.suppressedBy").value("test-user"))
                .andExpect(jsonPath("$.suppressedAt").exists())
                .andExpect(jsonPath("$.expiresAt").exists());

        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow();
        Finding finding = findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId()).stream()
                .findFirst()
                .orElseThrow();

        assertEquals("FALSE_POSITIVE", record.getSuppressionReason());
        assertEquals("validated compensating control", record.getSuppressionJustification());
        assertEquals("test-user", record.getSuppressedBy());
        assertNotNull(record.getSuppressedAt());
        assertNotNull(record.getSuppressedUntil());
        assertEquals(FindingStatus.SUPPRESSED, finding.getStatus());
        assertEquals("FALSE_POSITIVE: validated compensating control", finding.getSuppressionReason());
        assertNotNull(finding.getSuppressedUntil());
    }

    @Test
    void getCveDetailHandlesTextPayloadFieldsOnPostgres() throws Exception {
        String cveId = "ADV-DEMO-DETAIL-001";
        Vulnerability vulnerability = createVulnerability(cveId);
        vulnerability.setReferencesJson("""
                [{"url":"https://example.com/advisories/ADV-DEMO-DETAIL-001","source":"unit-test"}]
                """);
        vulnerability = vulnerabilityRepository.save(vulnerability);

        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "detail-text");

        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setTenant(tenant);
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setApplicabilityState(ApplicabilityState.APPLICABLE);
        state.setImpactState(ImpactState.IMPACTED);
        state.setEligibleForFinding(true);
        state.setMatchedBy("advisory-pkg-indexed-exact+version");
        state.setTraceJson("""
                {"matchedBy":"advisory-pkg-indexed-exact+version","why":"postgres-text-regression"}
                """);
        componentVulnerabilityStateRepository.save(state);

        mockMvc.perform(get("/api/cve-detail/{cveId}", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", "1")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.externalId").value(cveId))
                .andExpect(jsonPath("$.matchedSoftware[0].packageName").value("log4j-core"))
                .andExpect(jsonPath("$.matchedSoftware[0].impactState").value("IMPACTED"));
    }

    private Vulnerability createVulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Regression test CVE");
        vulnerability.setDescriptionSnippet("Regression test description");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.5);
        vulnerability.setPublishedAt(Instant.now());
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private InventoryComponent createComponent(Tenant tenant, String suffix) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName(suffix);
        asset.setIdentifier("asset:" + suffix);
        asset = assetRepository.save(asset);

        SbomUpload sbomUpload = new SbomUpload();
        sbomUpload.setTenant(tenant);
        sbomUpload.setAsset(asset);
        sbomUpload.setFormat(SbomFormat.CYCLONEDX);
        sbomUpload.setOriginalFilename(suffix + ".json");
        sbomUpload = sbomUploadRepository.save(sbomUpload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbomUpload);
        component.setEcosystem("maven");
        component.setPackageName("log4j-core");
        component.setVersion("2.17.0");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private void createOpenFinding(Tenant tenant, InventoryComponent component, Vulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(component.getAsset());
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy("cpe-indexed-direct+version");
        finding.setRiskScore(9.8);
        finding.setConfidenceScore(0.99);
        finding.setEvidence("{\"source\":\"test\"}");
        finding.setFirstObservedAt(Instant.now());
        finding.setLastObservedAt(Instant.now());
        finding.touch();
        findingRepository.save(finding);
    }
}
