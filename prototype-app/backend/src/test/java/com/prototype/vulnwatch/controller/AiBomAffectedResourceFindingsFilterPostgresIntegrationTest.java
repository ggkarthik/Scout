package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeclaredIdentityKind;
import com.prototype.vulnwatch.domain.AiBomResourceVulnerabilityLink;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.AiBomResourceVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Milestone 3 part 5.2 (API and query contracts): confirms the offset-page list path
 * ({@code FindingFilterSpecifications}) and the raw-SQL summary path
 * ({@code FindingProjectionQueryService}) agree on {@code affectedAiResourceId} /
 * {@code hasAffectedAiResource} -- exactly the risk the plan doc's 5.2 bullet names, since
 * these are two hand-written, independent predicate builders. Also confirms
 * {@code FindingResponse.affectedAiResources} is populated on the list path.
 */
@PostgresControllerIntegrationTest
class AiBomAffectedResourceFindingsFilterPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_affected_resource_findings_filter");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private TenantService tenantService;
    @Autowired private AssetRepository assetRepository;
    @Autowired private SbomUploadRepository sbomUploadRepository;
    @Autowired private InventoryComponentRepository inventoryComponentRepository;
    @Autowired private VulnerabilityRepository vulnerabilityRepository;
    @Autowired private FindingRepository findingRepository;
    @Autowired private BomSourceRepository bomSourceRepository;
    @Autowired private AiBomDeclaredResourceRepository declaredResourceRepository;
    @Autowired private AiBomResourceVulnerabilityLinkRepository linkRepository;
    @Autowired private FindingListProjectionService findingListProjectionService;

    private Asset seedAsset(Tenant tenant, String suffix) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName("ai-bom-filter-" + suffix);
        asset.setIdentifier("ai-bom-filter-" + suffix);
        return assetRepository.save(asset);
    }

    private InventoryComponent seedComponent(Tenant tenant, Asset asset, String suffix) {
        SbomUpload sbom = new SbomUpload();
        sbom.setTenant(tenant);
        sbom.setAsset(asset);
        sbom.setFormat(SbomFormat.CYCLONEDX);
        sbom.setOriginalFilename("ai-bom-filter-" + suffix + ".json");
        sbom = sbomUploadRepository.save(sbom);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbom);
        component.setPackageName("transformers-" + suffix);
        component.setVersion("4.38.0");
        component.setEcosystem("pypi");
        component.setPurl("pkg:pypi/transformers-" + suffix + "@4.38.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Finding seedOpenFinding(Tenant tenant, Asset asset, InventoryComponent component, String suffix) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2099-filter-" + suffix);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("AI-BOM affected-resource filter regression vulnerability");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.1);
        vulnerability.setLastModifiedAt(Instant.now());
        vulnerability = vulnerabilityRepository.save(vulnerability);

        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setRiskScore(7.5);
        finding.setMatchedBy("ai-bom-affected-resource-filter-it");
        return findingRepository.save(finding);
    }

    private AiBomDeclaredResource seedDeclaredResource(Tenant tenant, String suffix) {
        Instant now = Instant.now();
        BomSource source = new BomSource();
        source.setTenantId(tenant.getId());
        source.setBomType(BomType.AI_BOM);
        source.setRevision(1L);
        source.setCompleteness(BomSourceCompleteness.PARTIAL);
        source.setState(BomSourceState.ACTIVE);
        source.setCreatedAt(now);
        source.setUpdatedAt(now);
        source = bomSourceRepository.save(source);

        AiBomDeclaredResource declared = new AiBomDeclaredResource();
        declared.setTenantId(tenant.getId());
        declared.setSourceId(source.getId());
        declared.setBomId(java.util.UUID.randomUUID());
        declared.setResourceKind(AiBomDeclaredResourceKind.MODEL);
        declared.setName("llama-3-" + suffix);
        declared.setVersion("3.1");
        declared.setIdentityKind(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF);
        declared.setIdentityValue("llama-3-" + suffix + "@3.1");
        declared.setFirstDeclaredAt(now);
        declared.setLastDeclaredAt(now);
        return declaredResourceRepository.save(declared);
    }

    private void seedLink(Tenant tenant, AiBomDeclaredResource declared, Finding finding) {
        AiBomResourceVulnerabilityLink link = new AiBomResourceVulnerabilityLink();
        link.setTenantId(tenant.getId());
        link.setDeclaredResourceId(declared.getId());
        link.setFindingId(finding.getId());
        linkRepository.save(link);
    }

    @Test
    void listAndSummaryAgreeOnAffectedAiResourceId() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String suffix = "match-" + SEQUENCE.incrementAndGet();
        Asset asset = seedAsset(tenant, suffix);
        InventoryComponent component = seedComponent(tenant, asset, suffix);
        Finding linkedFinding = seedOpenFinding(tenant, asset, component, suffix);
        Finding unlinkedFinding = seedOpenFinding(tenant, asset, component, suffix + "-b");
        AiBomDeclaredResource declared = seedDeclaredResource(tenant, suffix);
        seedLink(tenant, declared, linkedFinding);
        findingListProjectionService.refreshTenant(tenant);

        mockMvc.perform(authedGet("/api/findings")
                        .param("assetName", asset.getName())
                        .param("affectedAiResourceId", declared.getId().toString())
                        .param("size", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].id").value(linkedFinding.getId().toString()))
                .andExpect(jsonPath("$.items[0].affectedAiResources[0].id").value(declared.getId().toString()))
                .andExpect(jsonPath("$.items[0].affectedAiResources[0].name").value(declared.getName()));

        mockMvc.perform(authedGet("/api/findings/summary")
                        .param("assetName", asset.getName())
                        .param("affectedAiResourceId", declared.getId().toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").value(1));

        // Sanity: without the filter both findings for this asset are visible.
        mockMvc.perform(authedGet("/api/findings")
                        .param("assetName", asset.getName())
                        .param("size", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(2));
        org.junit.jupiter.api.Assertions.assertEquals(unlinkedFinding.getStatus(), FindingStatus.OPEN);
    }

    @Test
    void listAndSummaryAgreeOnHasAffectedAiResource() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String suffix = "hasflag-" + SEQUENCE.incrementAndGet();
        Asset asset = seedAsset(tenant, suffix);
        InventoryComponent component = seedComponent(tenant, asset, suffix);
        Finding linkedFinding = seedOpenFinding(tenant, asset, component, suffix);
        seedOpenFinding(tenant, asset, component, suffix + "-b");
        AiBomDeclaredResource declared = seedDeclaredResource(tenant, suffix);
        seedLink(tenant, declared, linkedFinding);
        findingListProjectionService.refreshTenant(tenant);

        mockMvc.perform(authedGet("/api/findings")
                        .param("assetName", asset.getName())
                        .param("hasAffectedAiResource", "true")
                        .param("size", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].id").value(linkedFinding.getId().toString()));

        mockMvc.perform(authedGet("/api/findings/summary")
                        .param("assetName", asset.getName())
                        .param("hasAffectedAiResource", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").value(1));

        mockMvc.perform(authedGet("/api/findings")
                        .param("assetName", asset.getName())
                        .param("hasAffectedAiResource", "false")
                        .param("size", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].id").isNotEmpty());

        mockMvc.perform(authedGet("/api/findings/summary")
                        .param("assetName", asset.getName())
                        .param("hasAffectedAiResource", "false"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").value(1));
    }
}
