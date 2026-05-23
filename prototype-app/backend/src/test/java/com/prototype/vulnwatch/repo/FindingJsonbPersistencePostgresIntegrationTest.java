package com.prototype.vulnwatch.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class FindingJsonbPersistencePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_jsonb_persistence");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private TenantRepository tenantRepository;

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
    private FindingEventRepository findingEventRepository;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void persistsAndUpdatesJsonbEvidenceFields() {
        ensureDefaultTenant();
        Tenant tenant = tenantService.getDefaultTenant();
        Asset asset = createAsset(tenant);
        SbomUpload upload = createUpload(tenant, asset);
        InventoryComponent component = createComponent(tenant, asset, upload);
        Vulnerability vulnerability = createVulnerability();

        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy("purl-indexed-exact+version");
        finding.setRiskScore(7.5);
        finding.setConfidenceScore(0.82);
        finding.setEvidence("{\"source\":\"initial\",\"matchedBy\":\"purl-indexed-exact+version\"}");
        finding.setFirstObservedAt(Instant.now());
        finding.setLastObservedAt(Instant.now());
        finding.touch();
        finding = findingRepository.saveAndFlush(finding);

        FindingEvent event = new FindingEvent();
        event.setFinding(finding);
        event.setEventType("CREATED_BY_CORRELATION");
        event.setActor("system");
        event.setSummary("Finding created from correlation");
        event.setDetailsJson("{\"matchedBy\":\"purl-indexed-exact+version\",\"confidenceScore\":0.82}");
        event = findingEventRepository.saveAndFlush(event);

        finding.setEvidence("{\"source\":\"updated\",\"vexOverlay\":{\"status\":\"AFFECTED\"}}");
        finding.touch();
        findingRepository.saveAndFlush(finding);

        entityManager.clear();

        Finding reloadedFinding = findingRepository.findById(finding.getId()).orElseThrow();
        FindingEvent reloadedEvent = findingEventRepository.findById(event.getId()).orElseThrow();

        assertJsonEquals(
                "{\"source\":\"updated\",\"vexOverlay\":{\"status\":\"AFFECTED\"}}",
                reloadedFinding.getEvidence()
        );
        assertJsonEquals(
                "{\"matchedBy\":\"purl-indexed-exact+version\",\"confidenceScore\":0.82}",
                reloadedEvent.getDetailsJson()
        );
        assertNotNull(reloadedFinding.getUpdatedAt());
    }

    private Asset createAsset(Tenant tenant) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("ghcr-jsonb-test");
        asset.setIdentifier("ghcr.io/example/jsonb-test@sha256:test");
        return assetRepository.save(asset);
    }

    private SbomUpload createUpload(Tenant tenant, Asset asset) {
        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setOriginalFilename("jsonb-test.json");
        return sbomUploadRepository.save(upload);
    }

    private InventoryComponent createComponent(Tenant tenant, Asset asset, SbomUpload upload) {
        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem("apk");
        component.setPackageName("busybox");
        component.setVersion("1.36.1-r2");
        component.setPurl("pkg:apk/alpine/busybox@1.36.1-r2");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Vulnerability createVulnerability() {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2099-9999");
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("JSONB persistence regression");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(7.5);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private void ensureDefaultTenant() {
        tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(TenantService.DEFAULT_TENANT_NAME);
            return tenantRepository.save(tenant);
        });
    }

    private void assertJsonEquals(String expected, String actual) {
        try {
            JsonNode expectedNode = objectMapper.readTree(expected);
            JsonNode actualNode = objectMapper.readTree(actual);
            assertEquals(expectedNode, actualNode);
        } catch (Exception exception) {
            throw new AssertionError("Unable to compare JSON", exception);
        }
    }
}
