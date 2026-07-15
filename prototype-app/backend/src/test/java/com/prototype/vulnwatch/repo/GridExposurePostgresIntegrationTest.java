package com.prototype.vulnwatch.repo;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.service.FindingFilterSpecifications;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Covers the two new Grid Exposure query paths added to {@link FindingRepository} and
 * {@link FindingFilterSpecifications}: the grouped open-finding-by-asset-type-and-severity
 * count used by {@code DashboardService.getGridExposure}, and the {@code assetType} ad-hoc
 * filter used when a grid cell is clicked through to the findings list. Both must resolve
 * an asset either directly ({@code finding.asset}) or via the finding's component
 * ({@code finding.component.asset}).
 */
@PostgresIntegrationTest
class GridExposurePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("grid_exposure");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantService tenantService;

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

    @Test
    void countsAndFiltersOpenFindingsByDirectAndComponentResolvedAssetType() {
        ensureDefaultTenant();
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {

        Asset host = createAsset(tenant, AssetType.HOST, "grid-exposure-host");
        Asset application = createAsset(tenant, AssetType.APPLICATION, "grid-exposure-app");
        Vulnerability vulnerability = createVulnerability("CVE-2099-8888", "HIGH");

        Finding directHostFinding = createFinding(tenant, vulnerability);
        directHostFinding.setAsset(host);
        findingRepository.saveAndFlush(directHostFinding);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(application);
        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(application);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setOriginalFilename("grid-exposure.json");
        component.setSbomUpload(sbomUploadRepository.save(upload));
        component.setEcosystem("npm");
        component.setPackageName("grid-exposure-pkg");
        component.setVersion("1.0.0");
        component.setPurl("pkg:npm/grid-exposure-pkg@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        component = inventoryComponentRepository.save(component);

        Finding componentAppFinding = createFinding(tenant, vulnerability);
        componentAppFinding.setComponent(component);
        findingRepository.saveAndFlush(componentAppFinding);

        List<Object[]> counts = findingRepository.countOpenByAssetTypeAndSeverityForTenant(tenant.getId());
        assertTrue(counts.stream().anyMatch(row ->
                "HOST".equals(row[0]) && "HIGH".equals(row[1]) && ((Number) row[2]).longValue() >= 1L));
        assertTrue(counts.stream().anyMatch(row ->
                "APPLICATION".equals(row[0]) && "HIGH".equals(row[1]) && ((Number) row[2]).longValue() >= 1L));

        FindingsFilter hostFilter = new FindingsFilter(
                null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, List.of("HOST"));
        List<Finding> hostResults = findingRepository.findAll(FindingFilterSpecifications.byFilter(tenant, hostFilter));
        assertTrue(hostResults.stream().anyMatch(f -> f.getId().equals(directHostFinding.getId())));
        assertTrue(hostResults.stream().noneMatch(f -> f.getId().equals(componentAppFinding.getId())));

        FindingsFilter applicationFilter = new FindingsFilter(
                null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, List.of("APPLICATION"));
        List<Finding> applicationResults =
                findingRepository.findAll(FindingFilterSpecifications.byFilter(tenant, applicationFilter));
        assertTrue(applicationResults.stream().anyMatch(f -> f.getId().equals(componentAppFinding.getId())));
        assertTrue(applicationResults.stream().noneMatch(f -> f.getId().equals(directHostFinding.getId())));
        } finally {
            TenantContext.clear();
        }
    }

    private Asset createAsset(Tenant tenant, AssetType type, String name) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(type);
        asset.setName(name);
        asset.setIdentifier(name + "-identifier");
        return assetRepository.save(asset);
    }

    private Vulnerability createVulnerability(String externalId, String severity) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Grid exposure regression");
        vulnerability.setSeverity(severity);
        vulnerability.setCvssScore(7.5);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private Finding createFinding(Tenant tenant, Vulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy("purl-indexed-exact+version");
        finding.setRiskScore(7.5);
        finding.setConfidenceScore(0.82);
        finding.setEvidence("{\"source\":\"grid-exposure-it\"}");
        finding.setFirstObservedAt(Instant.now());
        finding.setLastObservedAt(Instant.now());
        finding.touch();
        return finding;
    }

    private void ensureDefaultTenant() {
        tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(TenantService.DEFAULT_TENANT_NAME);
            return tenantRepository.save(tenant);
        });
    }
}
