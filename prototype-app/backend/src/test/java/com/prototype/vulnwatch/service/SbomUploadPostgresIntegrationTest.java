package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SbomUploadPostgresIntegrationTest {

    private static final String API_KEY = "test-api-key";
    private static final String ASSET_IDENTIFIER = "app:postgres-sbom-delta";
    private static final String CVE_ID = "CVE-2099-6101";

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("sbom_upload");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private RiskPolicyRepository riskPolicyRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    private MockRestServiceServer server;

    @BeforeEach
    void enableAutomaticFindingGeneration() {
        server = MockRestServiceServer.bindTo(restTemplate).ignoreExpectOrder(true).build();
        Tenant tenant = tenantService.getDefaultTenant();
        RiskPolicy policy = riskPolicyRepository.findByTenant(tenant)
                .orElseGet(() -> {
                    RiskPolicy created = new RiskPolicy();
                    created.setTenant(tenant);
                    return created;
                });
        policy.setFindingGenerationMode(RiskPolicy.FindingGenerationMode.AUTO);
        policy.touch();
        riskPolicyRepository.save(policy);
    }

    @Test
    void sbomReuploadResolvesFindingAndUpdatesExposureOnRealPostgres() throws Exception {
        ingestAdvisory();

        JsonNode initialUpload = fetchSbom(
                "log4j-core-2.14.1.json",
                sbomPayload(
                        "2.14.1",
                        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"));
        assertEquals(1, initialUpload.path("componentsIngested").asInt());
        assertTrue(initialUpload.path("findingsGenerated").asInt() >= 0);

        Tenant tenant = tenantService.getDefaultTenant();
        Asset asset = assetRepository.findByTenantAndIdentifier(tenant, ASSET_IDENTIFIER).orElseThrow();
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(CVE_ID).orElseThrow();

        List<InventoryComponent> initialActiveComponents = inventoryComponentRepository
                .findByAssetAndComponentStatus(asset, InventoryComponentStatus.ACTIVE);
        assertEquals(1, initialActiveComponents.size());
        assertEquals("2.14.1", initialActiveComponents.get(0).getVersion());
        assertEquals(RiskPolicy.FindingGenerationMode.AUTO,
                riskPolicyRepository.findByTenant(tenant).orElseThrow().getFindingGenerationMode());
        assertFalse(vulnerabilityTargetRepository.findByVulnerability(vulnerability).isEmpty());
        assertTrue(vulnerabilityTargetRepository.findByVulnerability(vulnerability).stream()
                .anyMatch(target -> target.getTargetType() == VulnerabilityTargetType.CPE));
        assertFalse(inventoryComponentCpeMapRepository.findByComponent_Id(initialActiveComponents.get(0).getId()).isEmpty());
        List<ComponentVulnerabilityState> states = componentVulnerabilityStateRepository.findByTenantAndComponent(
                tenant,
                initialActiveComponents.get(0));
        assertEquals(1, states.size());
        assertEquals(ApplicabilityState.APPLICABLE, states.get(0).getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, states.get(0).getImpactState());
        assertTrue(states.get(0).isEligibleForFinding());

        List<Finding> openFindings = findingRepository.findByAssetAndStatus(asset, FindingStatus.OPEN);
        assertEquals(1, openFindings.size());
        assertTrue(openFindings.get(0).getMatchedBy() != null && openFindings.get(0).getMatchedBy().startsWith("cpe-"));

        OrgCveRecord initialExposure = orgCveRecordRepository
                .findByTenantAndVulnerability_Id(tenant, vulnerability.getId())
                .orElseThrow();
        assertTrue(initialExposure.isImpacted());
        assertEquals(ApplicabilityState.APPLICABLE, initialExposure.getApplicabilityState());
        assertTrue(initialExposure.getMatchedSoftwareCount() >= 1L);

        JsonNode secondUpload = fetchSbom(
                "log4j-core-2.17.2.json",
                sbomPayload(
                        "2.17.2",
                        "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.2",
                        "cpe:2.3:a:apache:log4j:2.17.2:*:*:*:*:*:*:*"));
        assertEquals(1, secondUpload.path("componentsIngested").asInt());
        assertEquals(0, secondUpload.path("findingsGenerated").asInt());

        List<InventoryComponent> activeComponents = inventoryComponentRepository
                .findByAssetAndComponentStatus(asset, InventoryComponentStatus.ACTIVE);
        List<InventoryComponent> retiredComponents = inventoryComponentRepository
                .findByAssetAndComponentStatus(asset, InventoryComponentStatus.RETIRED);
        assertEquals(1, activeComponents.size());
        assertEquals("2.17.2", activeComponents.get(0).getVersion());
        assertEquals(1, retiredComponents.size());
        assertEquals("2.14.1", retiredComponents.get(0).getVersion());

        List<Finding> allFindings = findingRepository.findByAsset(asset);
        assertEquals(1, allFindings.size());
        assertEquals(FindingStatus.RESOLVED, allFindings.get(0).getStatus());
        assertTrue(findingRepository.findByAssetAndStatus(asset, FindingStatus.OPEN).isEmpty());

        OrgCveRecord resolvedExposure = orgCveRecordRepository
                .findByTenantAndVulnerability_Id(tenant, vulnerability.getId())
                .orElseThrow();
        assertFalse(resolvedExposure.isImpacted());
        assertEquals(0L, resolvedExposure.getMatchedSoftwareCount());

        List<SbomUpload> uploads = sbomUploadRepository.findByAssetOrderByUploadedAtDesc(asset);
        assertEquals(2, uploads.size());
        assertTrue(uploads.stream().allMatch(upload -> upload.getStatus() == SbomIngestionStatus.SUCCESS));
    }

    private void ingestAdvisory() throws Exception {
        mockMvc.perform(post("/api/ingestion/advisories")
                        .header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "advisories": [
                                    {
                                      "externalId": "%s",
                                      "title": "Log4j regression advisory",
                                      "description": "Advisory used by postgres integration tests",
                                      "cvssScore": 9.3,
                                      "severity": "CRITICAL",
                                      "rules": [
                                        {
                                          "ecosystem": "maven",
                                          "packageName": "log4j-core",
                                          "versionStart": "2.0.0",
                                          "versionEnd": "2.17.1",
                                          "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                                        }
                                      ]
                                    }
                                  ]
                                }
                                """.formatted(CVE_ID)))
                .andExpect(status().isOk());
    }

    private JsonNode fetchSbom(String filename, String payload) throws Exception {
        String sourceUrl = "https://example.com/sbom/" + filename;
        server.reset();
        server.expect(once(), requestTo(sourceUrl))
                .andExpect(method(GET))
                .andRespond(withSuccess(payload, MediaType.APPLICATION_JSON));

        MvcResult result = mockMvc.perform(post("/api/sbom-fetch")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetType": "APPLICATION",
                                  "assetName": "postgres-sbom-delta",
                                  "assetIdentifier": "%s",
                                  "sourceUrl": "%s"
                                }
                                """.formatted(ASSET_IDENTIFIER, sourceUrl))
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isOk())
                .andReturn();

        server.verify();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String sbomPayload(String version, String purl, String cpe) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "log4j-core",
                      "version": "%s",
                      "purl": "%s",
                      "cpe": "%s"
                    }
                  ]
                }
                """.formatted(version, purl, cpe);
    }
}
