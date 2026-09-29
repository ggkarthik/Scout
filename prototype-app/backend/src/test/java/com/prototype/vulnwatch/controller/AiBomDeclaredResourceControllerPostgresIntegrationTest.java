package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
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
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.AiBomResourceVulnerabilityCorrelationService;
import com.prototype.vulnwatch.service.BomIngestionOrchestrator;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Milestone 3 part 5.3: the declared-resource read surface and the reviewed mapping workflow
 * (propose/approve/remove), driven through real HTTP so role-based authorization is actually
 * exercised -- same seeding convention as
 * {@link com.prototype.vulnwatch.service.AiBomResourceVulnerabilityCorrelationPostgresIntegrationTest}.
 */
@PostgresControllerIntegrationTest
class AiBomDeclaredResourceControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_declared_resource_controller");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private org.springframework.test.web.servlet.MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private TenantService tenantService;
    @Autowired private BomIngestionOrchestrator orchestrator;
    @Autowired private AiBomResourceVulnerabilityCorrelationService correlationService;
    @Autowired private AssetRepository assetRepository;
    @Autowired private InventoryComponentRepository inventoryComponentRepository;
    @Autowired private SbomUploadRepository sbomUploadRepository;
    @Autowired private VulnerabilityRepository vulnerabilityRepository;
    @Autowired private FindingRepository findingRepository;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    private static byte[] aiBomWithOneModel(String name, String version) {
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[{\"type\":\"machine-learning-model\",\"name\":\"" + name
                + "\",\"version\":\"" + version + "\",\"purl\":\"pkg:huggingface/" + name + "@" + version + "\"}]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] aiBomWithModelDependingOnLibrary(
            String modelName, String modelVersion, String libraryName, String libraryVersion) {
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":["
                + "{\"type\":\"machine-learning-model\",\"bom-ref\":\"model-1\",\"name\":\"" + modelName
                + "\",\"version\":\"" + modelVersion + "\",\"purl\":\"pkg:huggingface/" + modelName
                + "@" + modelVersion + "\"},"
                + "{\"type\":\"library\",\"bom-ref\":\"lib-1\",\"name\":\"" + libraryName
                + "\",\"version\":\"" + libraryVersion + "\",\"purl\":\"pkg:pypi/" + libraryName
                + "@" + libraryVersion + "\"}"
                + "],"
                + "\"dependencies\":[{\"ref\":\"model-1\",\"dependsOn\":[\"lib-1\"]}]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private Asset upload(Tenant tenant, String assetIdentifier, byte[] content) throws Exception {
        orchestrator.ingestFromUpload(
                tenant, BomType.AI_BOM, AssetType.APPLICATION, assetIdentifier, assetIdentifier,
                "acme", content, "ai-bom.json", BomSourceSelector.independent());
        return assetRepository.findByIdentifier(assetIdentifier).orElseThrow();
    }

    private void seedArtifact(Tenant tenant, UUID artifactId, String name) {
        Instant now = Instant.now();
        jdbc.update("""
                insert into ai_security_artifacts (
                    id, tenant_id, provider, provider_resource_id, artifact_type, native_kind,
                    name, account_id, region, active, attributes_json, first_observed_at, last_observed_at
                ) values (
                    :id, :tenantId, 'AWS', :providerResourceId, 'AI_MODEL', 'AWS_BEDROCK_MODEL',
                    :name, '123456789012', 'us-east-1', true, '{}'::jsonb, :now, :now
                )
                """,
                Map.of(
                        "id", artifactId,
                        "tenantId", tenant.getId(),
                        "providerResourceId", "arn:aws:bedrock:us-east-1::model/" + artifactId,
                        "name", name,
                        "now", java.sql.Timestamp.from(now)));
    }

    private Finding seedOpenVulnerabilityFindingAffecting(Tenant tenant, Asset asset, String libraryName, String libraryVersion) {
        SbomUpload sbom = new SbomUpload();
        sbom.setTenant(tenant);
        sbom.setAsset(asset);
        sbom.setFormat(SbomFormat.CYCLONEDX);
        sbom.setOriginalFilename("declared-resource-controller-it.json");
        sbom = sbomUploadRepository.save(sbom);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbom);
        component.setPackageName(libraryName);
        component.setVersion(libraryVersion);
        component.setEcosystem("pypi");
        component.setPurl("pkg:pypi/" + libraryName + "@" + libraryVersion);
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        component = inventoryComponentRepository.save(component);

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2099-" + SEQUENCE.incrementAndGet());
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Declared-resource controller IT vulnerability");
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
        finding.setMatchedBy("declared-resource-controller-it");
        return findingRepository.save(finding);
    }

    private UUID onlyDeclaredResourceIdViaList(String... expectedNames) throws Exception {
        MvcResult result = mockMvc.perform(asAnalyst(authedGet("/api/bom/declared-resources")))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode array = objectMapper.readTree(result.getResponse().getContentAsString());
        for (JsonNode node : array) {
            for (String name : expectedNames) {
                if (name.equals(node.get("name").asText())) {
                    return UUID.fromString(node.get("id").asText());
                }
            }
        }
        throw new AssertionError("declared resource not found in list response");
    }

    @Test
    void listAndDetailExposeTheDeclaredResourceAndItsProjectionStatus() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String assetIdentifier = "declared-resource-detail-" + SEQUENCE.incrementAndGet();
        String modelName = "detail-model-" + SEQUENCE.get();
        upload(tenant, assetIdentifier, aiBomWithOneModel(modelName, "1.0"));

        UUID resourceId = onlyDeclaredResourceIdViaList(modelName);

        mockMvc.perform(asAnalyst(authedGet("/api/bom/declared-resources/{id}", resourceId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resource.name").value(modelName))
                .andExpect(jsonPath("$.resource.deploymentState").value("UNVERIFIED"))
                .andExpect(jsonPath("$.sourceBomType").value("AI_BOM"));
    }

    @Test
    void unlinkedResourceAppearsAsASetupActionNotAPolicyViolation() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String assetIdentifier = "declared-resource-setup-action-" + SEQUENCE.incrementAndGet();
        String modelName = "setup-action-model-" + SEQUENCE.get();
        upload(tenant, assetIdentifier, aiBomWithOneModel(modelName, "1.0"));

        MvcResult result = mockMvc.perform(asAnalyst(authedGet("/api/bom/declared-resources/setup-actions")))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode actions = objectMapper.readTree(result.getResponse().getContentAsString());
        boolean found = false;
        for (JsonNode action : actions) {
            if (action.get("title").asText().contains(modelName)) {
                found = true;
                assertEquals("UNLINKED", action.get("category").asText());
            }
        }
        assertTrue(found, "expected an UNLINKED setup action for the unverified declared resource");
    }

    @Test
    void proposeThenApproveLinksTheDeclaredResourceAndFindingsAffectingItAreReturned() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String assetIdentifier = "declared-resource-lifecycle-" + SEQUENCE.incrementAndGet();
        String modelName = "lifecycle-model-" + SEQUENCE.get();
        Asset asset = upload(tenant, assetIdentifier,
                aiBomWithModelDependingOnLibrary(modelName, "1.0", "transformers", "4.38.0"));
        UUID resourceId = onlyDeclaredResourceIdViaList(modelName);

        UUID artifactId = UUID.randomUUID();
        seedArtifact(tenant, artifactId, modelName);

        // Propose is reachable by a plain analyst (no creator key).
        mockMvc.perform(asAnalyst(authedPost("/api/bom/declared-resources/{id}/mapping/propose", resourceId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"artifactId\":\"" + artifactId + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deploymentState").value("UNVERIFIED"))
                .andExpect(jsonPath("$.proposedArtifactId").value(artifactId.toString()));

        // Approve requires an elevated role -- a plain analyst is forbidden.
        mockMvc.perform(asAnalyst(authedPost("/api/bom/declared-resources/{id}/mapping/approve", resourceId)))
                .andExpect(status().isForbidden());

        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/declared-resources/{id}/mapping/approve", resourceId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deploymentState").value("LINKED"))
                .andExpect(jsonPath("$.linkedArtifactId").value(artifactId.toString()))
                .andExpect(jsonPath("$.linkMethod").value("REVIEWED"));

        Finding finding = seedOpenVulnerabilityFindingAffecting(tenant, asset, "transformers", "4.38.0");
        correlationService.reconcileAllForTenant(tenant);

        MvcResult findingsResult = mockMvc.perform(
                        asAnalyst(authedGet("/api/bom/declared-resources/{id}/findings", resourceId)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode findings = objectMapper.readTree(findingsResult.getResponse().getContentAsString());
        assertEquals(1, findings.size());
        assertEquals(finding.getId().toString(), findings.get(0).get("id").asText());

        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/declared-resources/{id}/mapping/remove", resourceId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deploymentState").value("UNVERIFIED"))
                .andExpect(jsonPath("$.linkedArtifactId").doesNotExist());
    }
}
