package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.dto.SoftwareIdentityFunnelResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SoftwareIdentityReadServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("software_identity_read_service");

    private static final AtomicLong TENANT_SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private SoftwareIdentityRepository softwareIdentityRepository;

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
    private SoftwareIdentityReadService softwareIdentityReadService;

    @Test
    void funnelCountsSoftwareWithOpenFindingEvenWhenNoImpactedComponentVulnerabilityState() {
        // Regression: previously the funnel's "Software With CVEs" count joined
        // component_vulnerability_states (impact_state='IMPACTED'). The Software
        // Identities table, however, derives its CVE count from findings with
        // status='OPEN'. The two sources can disagree (e.g. an OPEN finding that
        // outlived its IMPACTED CVS row), so the funnel is now aligned to use the
        // findings table — the same source as the table column it should match.

        String suffix = "openfinding-" + TENANT_SEQUENCE.incrementAndGet();
        Tenant tenant = createTenant(suffix);
        SoftwareIdentity identity = createIdentity(suffix);
        Asset asset = createAsset(tenant, "host-" + suffix);
        SbomUpload sbom = createSbom(tenant, asset, suffix);
        InventoryComponent component = createActiveComponent(tenant, asset, sbom, identity, suffix);
        Vulnerability vulnerability = createVulnerability("CVE-2099-" + suffix);
        createOpenFinding(tenant, asset, component, vulnerability);
        // Intentionally no ComponentVulnerabilityState row — the old SQL would
        // have reported softwareWithVulnerabilities = 0 for this fixture.

        SoftwareIdentityFunnelResponse funnel = softwareIdentityReadService.getFunnel(tenant);

        assertNotNull(funnel);
        assertEquals(1L, funnel.recordsFound());
        assertEquals(1L, funnel.uniqueSoftware());
        assertEquals(1L, funnel.softwareWithVulnerabilities());
        assertEquals(1L, funnel.softwareWithFindings());
    }

    @Test
    void funnelDoesNotCountResolvedFindings() {
        String suffix = "resolved-" + TENANT_SEQUENCE.incrementAndGet();
        Tenant tenant = createTenant(suffix);
        SoftwareIdentity identity = createIdentity(suffix);
        Asset asset = createAsset(tenant, "host-" + suffix);
        SbomUpload sbom = createSbom(tenant, asset, suffix);
        InventoryComponent component = createActiveComponent(tenant, asset, sbom, identity, suffix);
        Vulnerability vulnerability = createVulnerability("CVE-2099-" + suffix);
        Finding finding = createOpenFinding(tenant, asset, component, vulnerability);
        finding.setStatus(FindingStatus.RESOLVED);
        findingRepository.save(finding);

        SoftwareIdentityFunnelResponse funnel = softwareIdentityReadService.getFunnel(tenant);

        assertEquals(1L, funnel.recordsFound());
        assertEquals(1L, funnel.uniqueSoftware());
        assertEquals(0L, funnel.softwareWithVulnerabilities());
        assertEquals(0L, funnel.softwareWithFindings());
    }

    private Tenant createTenant(String suffix) {
        Tenant tenant = new Tenant();
        tenant.setName("Funnel IT Tenant " + suffix);
        tenant.setSlug("funnel-it-" + suffix);
        tenant.setStatus("ACTIVE");
        tenant.setPlanCode("pilot");
        return tenantRepository.save(tenant);
    }

    private SoftwareIdentity createIdentity(String suffix) {
        SoftwareIdentity identity = new SoftwareIdentity();
        identity.setCanonicalKey("vendor-" + suffix + "::product-" + suffix);
        identity.setDisplayName("Funnel Test Software " + suffix);
        identity.setVendor("vendor-" + suffix);
        identity.setProduct("product-" + suffix);
        return softwareIdentityRepository.save(identity);
    }

    private Asset createAsset(Tenant tenant, String name) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName(name);
        asset.setIdentifier("asset:" + name + "-" + UUID.randomUUID());
        return assetRepository.save(asset);
    }

    private SbomUpload createSbom(Tenant tenant, Asset asset, String suffix) {
        SbomUpload sbom = new SbomUpload();
        sbom.setTenant(tenant);
        sbom.setAsset(asset);
        sbom.setFormat(SbomFormat.CYCLONEDX);
        sbom.setOriginalFilename("funnel-it-" + suffix + ".json");
        return sbomUploadRepository.save(sbom);
    }

    private InventoryComponent createActiveComponent(
            Tenant tenant,
            Asset asset,
            SbomUpload sbom,
            SoftwareIdentity identity,
            String suffix
    ) {
        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbom);
        component.setSoftwareIdentity(identity);
        component.setEcosystem("maven");
        component.setPackageName("funnel-it-package-" + suffix);
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/" + identity.getVendor() + "/" + identity.getProduct() + "@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Vulnerability createVulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Funnel regression vulnerability");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.1);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private Finding createOpenFinding(
            Tenant tenant,
            Asset asset,
            InventoryComponent component,
            Vulnerability vulnerability
    ) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setRiskScore(8.1);
        finding.setMatchedBy("funnel-it");
        return findingRepository.save(finding);
    }
}
