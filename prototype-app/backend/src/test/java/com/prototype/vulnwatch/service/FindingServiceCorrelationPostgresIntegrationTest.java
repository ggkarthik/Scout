package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.util.CpeUtil;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
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
class FindingServiceCorrelationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_correlation");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private FindingService findingService;

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
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Autowired
    private InventoryComponentCpeMappingService inventoryComponentCpeMappingService;

    @Autowired
    private CpeDimensionService cpeDimensionService;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private RiskPolicyRepository riskPolicyRepository;

    @Autowired
    private SoftwareInventorySyncService softwareInventorySyncService;

    @BeforeEach
    void resetToManualFindingGeneration() {
        setFindingGenerationMode(RiskPolicy.FindingGenerationMode.MANUAL);
    }

    @Test
    void manualModeDoesNotAutoCreateFindingDuringRecompute() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "manual-mode-pg",
                "maven",
                "log4j-core",
                "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-5000", VulnerabilitySource.NVD, "HIGH", 8.4);
        createCpeTarget(
                vulnerability,
                "nvd",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "2.0.0",
                "2.17.1"
        );

        int active = findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId());
        assertEquals(0, active);
        assertTrue(findingRepository.findByComponent(fixture.component()).isEmpty());
    }

    @Test
    void autoModeCreatesAffectedFindingDuringRecompute() {
        setFindingGenerationMode(RiskPolicy.FindingGenerationMode.AUTO);
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "auto-mode-pg",
                "maven",
                "log4j-core",
                "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-5001", VulnerabilitySource.NVD, "HIGH", 8.4);
        createCpeTarget(
                vulnerability,
                "nvd",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "2.0.0",
                "2.17.1"
        );

        int active = findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId());
        assertEquals(1, active);

        List<Finding> findings = findingRepository.findByComponent(fixture.component());
        assertEquals(1, findings.size());

        Finding finding = findings.get(0);
        assertEquals(FindingStatus.OPEN, finding.getStatus());
        assertEquals(FindingDecisionState.AFFECTED, finding.getDecisionState());
        assertTrue(finding.getMatchedBy().startsWith("cpe-"));
        assertNotNull(finding.getEvidence());
    }

    private void setFindingGenerationMode(RiskPolicy.FindingGenerationMode mode) {
        Tenant tenant = tenantService.getDefaultTenant();
        RiskPolicy policy = riskPolicyRepository.findByTenant(tenant)
                .orElseGet(() -> {
                    RiskPolicy created = new RiskPolicy();
                    created.setTenant(tenant);
                    return created;
                });
        policy.setFindingGenerationMode(mode);
        policy.touch();
        riskPolicyRepository.save(policy);
    }

    private TestFixture createAssetAndComponent(
            Tenant tenant,
            String suffix,
            String ecosystem,
            String packageName,
            String version,
            String purl,
            String cpe
    ) {
        String token = suffix + "-" + UUID.randomUUID().toString().substring(0, 8);

        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName("asset-" + token);
        asset.setIdentifier("app:" + token);
        asset.setBusinessCriticality(BusinessCriticality.MEDIUM);
        asset.setState(AssetState.ACTIVE);
        asset.setLastInventoryAt(Instant.now());
        asset = assetRepository.save(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setStatus(SbomIngestionStatus.SUCCESS);
        upload.setOriginalFilename("fixture-" + token + ".json");
        upload = sbomUploadRepository.save(upload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem(ecosystem.toLowerCase(Locale.ROOT));
        component.setPackageName(packageName.toLowerCase(Locale.ROOT));
        component.setVersion(version);
        component.setPurl(purl);
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        component = inventoryComponentRepository.save(component);

        inventoryComponentCpeMappingService.syncActiveComponentMappings(component, List.of(cpe));
        softwareInventorySyncService.syncFromInventoryDelta(tenant, List.of(component), Instant.now());

        return new TestFixture(asset, component);
    }

    private Vulnerability createVulnerability(String externalId, VulnerabilitySource source, String severity, double cvss) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId + "-" + UUID.randomUUID().toString().substring(0, 8));
        vulnerability.setSource(source);
        vulnerability.setTitle(externalId);
        vulnerability.setSeverity(severity);
        vulnerability.setCvssScore(cvss);
        vulnerability.setDescription("test");
        vulnerability.touch();
        return vulnerabilityRepository.save(vulnerability);
    }

    private void createCpeTarget(
            Vulnerability vulnerability,
            String source,
            String cpe,
            String versionStart,
            String versionEnd
    ) {
        String normalizedCpe = CpeUtil.normalizeCpe23(cpe);
        CpeDim cpeDim = cpeDimensionService.resolveOrCreate(normalizedCpe);

        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVulnerability(vulnerability);
        target.setTargetType(VulnerabilityTargetType.CPE);
        target.setNormalizedTargetKey(normalizedCpe);
        target.setSource(source);
        target.setCpe(normalizedCpe);
        target.setCpeDim(cpeDim);
        target.setCpeWildcardScore(1);
        target.setVersionScheme(VersionScheme.UNKNOWN);
        target.setConstraintType(
                versionStart == null && versionEnd == null
                        ? VulnerabilityConstraintType.NONE
                        : VulnerabilityConstraintType.RANGE
        );
        target.setVersionStart(versionStart);
        target.setStartInclusive(Boolean.TRUE);
        target.setVersionEnd(versionEnd);
        target.setEndInclusive(Boolean.TRUE);
        target.setKbVersion("test-kb");
        vulnerabilityTargetRepository.save(target);
    }

    private record TestFixture(Asset asset, InventoryComponent component) {
    }
}
