package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.dto.BomComponentSummaryResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class BomInventoryReadServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_inventory_read_service");

    private static final AtomicLong TENANT_SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private BomInventoryReadService bomInventoryReadService;

    @BeforeEach
    void clearFixtures() {
        jdbcTemplate.execute("TRUNCATE TABLE tenant_default.assets CASCADE");
        jdbcTemplate.execute("TRUNCATE TABLE platform.vulnerabilities CASCADE");
    }

    @Test
    void bomComponentSummariesBreakOpenFindingsDownBySeverity() {
        // The BOM Components Findings column renders one chip per severity bucket, so
        // criticalFindingCount/highFindingCount must agree with the vulnerability/risk-score
        // -derived severity used everywhere else in the product.
        String suffix = "bom-severity-" + TENANT_SEQUENCE.incrementAndGet();
        Tenant tenant = tenantService.getDefaultTenant();
        Asset asset = createApplicationAsset(tenant, "app-" + suffix);
        SbomUpload sbom = createSbom(tenant, asset, suffix);
        InventoryComponent component = createActiveComponent(tenant, asset, sbom, suffix);

        Vulnerability criticalVulnerability = createVulnerability("CVE-2099-critical-" + suffix, "CRITICAL");
        createOpenFinding(tenant, asset, component, criticalVulnerability);

        Vulnerability highVulnerability = createVulnerability("CVE-2099-high-" + suffix, "HIGH");
        createOpenFinding(tenant, asset, component, highVulnerability);

        List<BomComponentSummaryResponse> summaries = bomInventoryReadService.getBomComponentSummaries(tenant, 0, 50);

        BomComponentSummaryResponse summary = summaries.stream()
                .filter(item -> item.componentId().equals(component.getId().toString()))
                .findFirst()
                .orElseThrow();

        assertEquals(2, summary.findingCount());
        assertEquals(1, summary.criticalFindingCount());
        assertEquals(1, summary.highFindingCount());
    }

    private Asset createApplicationAsset(Tenant tenant, String name) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName(name);
        asset.setIdentifier("asset:" + name + "-" + UUID.randomUUID());
        return assetRepository.save(asset);
    }

    private SbomUpload createSbom(Tenant tenant, Asset asset, String suffix) {
        SbomUpload sbom = new SbomUpload();
        sbom.setTenant(tenant);
        sbom.setAsset(asset);
        sbom.setFormat(SbomFormat.CYCLONEDX);
        sbom.setOriginalFilename("bom-inventory-it-" + suffix + ".json");
        return sbomUploadRepository.save(sbom);
    }

    private InventoryComponent createActiveComponent(Tenant tenant, Asset asset, SbomUpload sbom, String suffix) {
        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbom);
        component.setEcosystem("maven");
        component.setPackageName("bom-it-package-" + suffix);
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/bom-it/" + suffix + "@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Vulnerability createVulnerability(String externalId, String severity) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("BOM inventory regression vulnerability");
        vulnerability.setSeverity(severity);
        vulnerability.setCvssScore("CRITICAL".equals(severity) ? 9.5 : 8.1);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private Finding createOpenFinding(Tenant tenant, Asset asset, InventoryComponent component, Vulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setRiskScore(vulnerability.getCvssScore());
        finding.setMatchedBy("bom-inventory-it");
        return findingRepository.save(finding);
    }
}
