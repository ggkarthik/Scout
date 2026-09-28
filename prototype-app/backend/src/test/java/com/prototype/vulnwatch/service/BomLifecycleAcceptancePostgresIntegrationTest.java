package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Acceptance criteria for the common BOM lifecycle, driven through the real ingestion path.
 *
 * <p>These cannot be unit tested: they depend on the orchestrator resolving a source, the
 * inventory ingester upserting components, and the contribution reconciler agreeing on what
 * each source vouches for -- across two separate ingests.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        // The sweep would otherwise reconstruct sources underneath these assertions.
        "app.bom.contribution-backfill.initial-delay-ms=600000"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class BomLifecycleAcceptancePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_lifecycle_acceptance");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private BomIngestionOrchestrator orchestrator;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private BomSourceRepository bomSourceRepository;

    @Autowired
    private BomComponentContributionRepository contributionRepository;

    private static byte[] cycloneDx(String... purls) {
        StringBuilder components = new StringBuilder();
        for (int i = 0; i < purls.length; i++) {
            String purl = purls[i];
            String name = purl.substring(purl.indexOf('/') + 1, purl.indexOf('@'));
            String version = purl.substring(purl.indexOf('@') + 1);
            if (i > 0) {
                components.append(',');
            }
            components.append("{\"type\":\"library\",\"name\":\"").append(name)
                    .append("\",\"version\":\"").append(version)
                    .append("\",\"purl\":\"").append(purl).append("\"}");
        }
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[" + components + "]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private void upload(Tenant tenant, BomType bomType, String assetIdentifier, byte[] content)
            throws Exception {
        orchestrator.ingestFromUpload(
                tenant,
                bomType,
                AssetType.APPLICATION,
                assetIdentifier,
                assetIdentifier,
                "acme",
                content,
                bomType.name().toLowerCase() + ".json",
                // No source named: an independent source, which is the default for a manual upload.
                BomSourceSelector.independent());
    }

    private List<InventoryComponent> activeComponents(String assetIdentifier) {
        return inventoryComponentRepository.findAll().stream()
                .filter(component -> component.getAsset() != null
                        && assetIdentifier.equals(component.getAsset().getIdentifier()))
                .filter(component -> component.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .toList();
    }

    /**
     * The regression that motivated all of this. An AI-BOM declares AI resources, not the
     * asset's whole software inventory, so uploading one must not retire the components an
     * earlier SBOM reported -- which would auto-close their findings as AUTO_COMPONENT_REMOVED
     * and report live vulnerabilities as fixed.
     */
    @Test
    void anAiBomDoesNotRetireTheComponentsAnEarlierSbomReported() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "acceptance-app-" + SEQUENCE.incrementAndGet();

        upload(tenant, BomType.SBOM, asset,
                cycloneDx("pkg:npm/lodash@4.17.20", "pkg:npm/express@4.18.2"));
        assertEquals(2, activeComponents(asset).size());

        upload(tenant, BomType.AI_BOM, asset, cycloneDx("pkg:pypi/torch@2.1.0"));

        List<String> purls = activeComponents(asset).stream()
                .map(InventoryComponent::getPurl)
                .sorted()
                .toList();
        assertEquals(3, purls.size(),
                "the SBOM's components must survive a partial AI-BOM upload, got " + purls);
        assertTrue(purls.contains("pkg:npm/lodash@4.17.20"), purls.toString());
        assertTrue(purls.contains("pkg:npm/express@4.18.2"), purls.toString());
        assertTrue(purls.contains("pkg:pypi/torch@2.1.0"), purls.toString());
    }

    /** Plan: overlapping uploads produce one component for the same resolved identity. */
    @Test
    void anSbomThenAnAiBomDeclaringTheSameComponentYieldOneComponent() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "acceptance-overlap-fwd-" + SEQUENCE.incrementAndGet();

        upload(tenant, BomType.SBOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));
        upload(tenant, BomType.AI_BOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));

        assertEquals(1, activeComponents(asset).size(),
                "one resolved identity is one inventory component regardless of how many "
                        + "documents report it");
    }

    /** The same, in the other order: order of arrival must not change the outcome. */
    @Test
    void anAiBomThenAnSbomDeclaringTheSameComponentYieldOneComponent() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "acceptance-overlap-rev-" + SEQUENCE.incrementAndGet();

        upload(tenant, BomType.AI_BOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));
        upload(tenant, BomType.SBOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));

        assertEquals(1, activeComponents(asset).size());
    }

    /**
     * Two manual uploads name no source, so they are two independent sources. Both should end
     * up vouching for the shared component, and the component's aggregate evidence should
     * reflect live support rather than a conflict.
     */
    @Test
    void twoIndependentSourcesBothVouchForTheSharedComponent() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "acceptance-claims-" + SEQUENCE.incrementAndGet();

        upload(tenant, BomType.SBOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));
        upload(tenant, BomType.AI_BOM, asset, cycloneDx("pkg:npm/lodash@4.17.20"));

        List<InventoryComponent> components = activeComponents(asset);
        assertEquals(1, components.size());
        UUID componentId = components.get(0).getId();

        List<BomSource> sources = bomSourceRepository.findAll().stream()
                .filter(source -> source.getAssetId() != null
                        && source.getAssetId().equals(components.get(0).getAsset().getId()))
                .toList();
        assertEquals(2, sources.size(),
                "a manual upload that names no source creates an independent one");

        List<BomComponentContribution> claims =
                contributionRepository.findByInventoryComponentId(componentId);
        assertEquals(2, claims.size(), "each source records its own claim on the component");
        assertTrue(claims.stream()
                        .allMatch(claim -> claim.getContributionState() == BomContributionState.SUPPORTED),
                "both sources still report the component");
        assertTrue(claims.stream().noneMatch(BomComponentContribution::isAuthoritativeAbsence),
                "neither upload asserted completeness, so neither may assert absence");

        assertEquals(BomEvidenceState.SUPPORTED,
                inventoryComponentRepository.findById(componentId).orElseThrow().getBomEvidenceState());
    }
}
