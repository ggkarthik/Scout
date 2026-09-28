package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
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
 * End-to-end acceptance for Milestone 2 part 4.1 (the declared-inventory writer), driven
 * through the real ingestion path -- same pattern as
 * {@link BomLifecycleAcceptancePostgresIntegrationTest}.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.bom.contribution-backfill.initial-delay-ms=600000"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomDeclaredInventoryPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_declared_inventory");

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
    private AiBomDeclaredResourceRepository declaredResourceRepository;

    private record ComponentSpec(String type, String name, String version, String purl, String bomRef) {
        static ComponentSpec of(String type, String name, String version, String purl, String bomRef) {
            return new ComponentSpec(type, name, version, purl, bomRef);
        }
    }

    private static byte[] aiBom(ComponentSpec... specs) {
        StringBuilder components = new StringBuilder();
        for (int i = 0; i < specs.length; i++) {
            if (i > 0) {
                components.append(',');
            }
            ComponentSpec spec = specs[i];
            components.append("{\"type\":\"").append(spec.type())
                    .append("\",\"name\":\"").append(spec.name()).append('"');
            if (spec.version() != null) {
                components.append(",\"version\":\"").append(spec.version()).append('"');
            }
            if (spec.purl() != null) {
                components.append(",\"purl\":\"").append(spec.purl()).append('"');
            }
            if (spec.bomRef() != null) {
                components.append(",\"bom-ref\":\"").append(spec.bomRef()).append('"');
            }
            components.append('}');
        }
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[" + components + "]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private void upload(Tenant tenant, String assetIdentifier, byte[] content, BomSourceSelector selector)
            throws Exception {
        orchestrator.ingestFromUpload(
                tenant, BomType.AI_BOM, AssetType.APPLICATION, assetIdentifier, assetIdentifier,
                "acme", content, "ai-bom.json", selector);
    }

    private BomSource sourceForAsset(Tenant tenant, UUID assetId) {
        return bomSourceRepository.findAll().stream()
                .filter(source -> tenant.getId().equals(source.getTenantId())
                        && assetId.equals(source.getAssetId())
                        && source.getBomType() == BomType.AI_BOM)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no AI_BOM source found for asset " + assetId));
    }

    private UUID resolveAssetId(String assetIdentifier) {
        return inventoryComponentRepository.findAll().stream()
                .filter(component -> component.getAsset() != null
                        && assetIdentifier.equals(component.getAsset().getIdentifier()))
                .findFirst()
                .map(InventoryComponent::getAsset)
                .map(com.prototype.vulnwatch.domain.Asset::getId)
                .orElseThrow(() -> new AssertionError("no resolved asset for " + assetIdentifier));
    }

    /**
     * The declared-inventory analogue of the M1 classification acceptance test: a model and a
     * dataset both stay out of software inventory but must land in the declared table, correctly
     * split by kind, and unverified until something actually links them to a deployment.
     */
    @Test
    void aModelAndADatasetAreDeclaredWhileTheirLibraryDependencyEntersSoftwareInventory() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "declared-inventory-" + SEQUENCE.incrementAndGet();

        upload(tenant, asset, aiBom(
                ComponentSpec.of("machine-learning-model", "llama-3", "3.1",
                        "pkg:huggingface/llama-3@3.1", null),
                ComponentSpec.of("dataset", "training-corpus", "2024.1", null, "corpus-ref"),
                ComponentSpec.of("library", "transformers", "4.38.0", "pkg:pypi/transformers@4.38.0", null)
        ), BomSourceSelector.independent());

        List<String> purls = inventoryComponentRepository.findAll().stream()
                .filter(c -> c.getAsset() != null && asset.equals(c.getAsset().getIdentifier()))
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(InventoryComponent::getPurl)
                .toList();
        assertEquals(List.of("pkg:pypi/transformers@4.38.0"), purls,
                "only the software dependency belongs in software inventory");

        UUID assetId = resolveAssetId(asset);
        BomSource source = sourceForAsset(tenant, assetId);
        List<AiBomDeclaredResource> declared = declaredResourceRepository.findBySourceId(source.getId());

        assertEquals(2, declared.size(), "the model and the dataset must both be declared, got " + declared);
        assertTrue(declared.stream().allMatch(r -> r.getDeploymentState() == AiBomDeploymentState.UNVERIFIED),
                "a declaration is not a deployment until something verifies it");
        assertEquals(1, declared.stream().filter(r -> r.getResourceKind() == AiBomDeclaredResourceKind.MODEL).count());
        assertEquals(1, declared.stream().filter(r -> r.getResourceKind() == AiBomDeclaredResourceKind.DATASET).count());
    }

    /**
     * Plan §4.1: replacement must update the same declared resource, not create a second one --
     * mirrors M1's "one resolved identity is one record" rule, applied to declared resources.
     */
    @Test
    void replacingASourceUpdatesTheSameDeclaredResourceRatherThanDuplicatingIt() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "declared-replace-" + SEQUENCE.incrementAndGet();

        upload(tenant, asset, aiBom(
                ComponentSpec.of("model", "llama-3", "3.1", "pkg:huggingface/llama-3@3.1", null),
                ComponentSpec.of("library", "transformers", "4.38.0", "pkg:pypi/transformers@4.38.0", null)
        ), BomSourceSelector.independent());

        UUID assetId = resolveAssetId(asset);
        BomSource source = sourceForAsset(tenant, assetId);
        List<AiBomDeclaredResource> firstPass = declaredResourceRepository.findBySourceId(source.getId());
        assertEquals(1, firstPass.size());
        UUID declaredId = firstPass.get(0).getId();
        var firstDeclaredAt = firstPass.get(0).getFirstDeclaredAt();

        Thread.sleep(5);
        upload(tenant, asset, aiBom(
                ComponentSpec.of("model", "llama-3", "3.1", "pkg:huggingface/llama-3@3.1", null),
                ComponentSpec.of("library", "transformers", "4.38.1", "pkg:pypi/transformers@4.38.1", null)
        ), new BomSourceSelector(source.getId(), null, BomSourceCompleteness.PARTIAL, Set.of(), null));

        List<AiBomDeclaredResource> secondPass = declaredResourceRepository.findBySourceId(source.getId());
        assertEquals(1, secondPass.size(), "a replacement must not duplicate the declared resource");
        assertEquals(declaredId, secondPass.get(0).getId());
        assertEquals(firstDeclaredAt, secondPass.get(0).getFirstDeclaredAt(),
                "firstDeclaredAt must survive a replacement");
        assertTrue(secondPass.get(0).getLastDeclaredAt().isAfter(firstDeclaredAt),
                "lastDeclaredAt must advance on a replacement");
    }

    /**
     * Plan §4.1: "never merge by display name." Two independent sources declaring what looks
     * like the same model (same name/version, no purl or digest to prove it) must stay two rows
     * -- the unique constraint is scoped to (tenant, source, identity), not tenant-wide.
     */
    @Test
    void twoIndependentSourcesDeclaringTheSameNamedModelStayAsSeparateDeclarations() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String assetA = "declared-independent-a-" + SEQUENCE.incrementAndGet();
        String assetB = "declared-independent-b-" + SEQUENCE.incrementAndGet();

        ComponentSpec ambiguousModel = ComponentSpec.of("model", "classifier", "1.0", null, null);
        upload(tenant, assetA, aiBom(ambiguousModel,
                ComponentSpec.of("library", "numpy-a", "1.0", "pkg:pypi/numpy-a@1.0", null)),
                BomSourceSelector.independent());
        upload(tenant, assetB, aiBom(ambiguousModel,
                ComponentSpec.of("library", "numpy-b", "1.0", "pkg:pypi/numpy-b@1.0", null)),
                BomSourceSelector.independent());

        BomSource sourceA = sourceForAsset(tenant, resolveAssetId(assetA));
        BomSource sourceB = sourceForAsset(tenant, resolveAssetId(assetB));
        assertNotEquals(sourceA.getId(), sourceB.getId());

        List<AiBomDeclaredResource> declaredA = declaredResourceRepository.findBySourceId(sourceA.getId());
        List<AiBomDeclaredResource> declaredB = declaredResourceRepository.findBySourceId(sourceB.getId());

        assertEquals(1, declaredA.size());
        assertEquals(1, declaredB.size());
        assertNotEquals(declaredA.get(0).getId(), declaredB.get(0).getId(),
                "two sources' declarations of a same-named model must never collapse into one row");
    }
}
