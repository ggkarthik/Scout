package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomLinkMethod;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * End-to-end acceptance for Milestone 2 part 4.2 (automatic deployment linking), driven through
 * the real ingestion path -- same pattern as {@link AiBomDeclaredInventoryPostgresIntegrationTest}.
 * {@code ai_security_artifacts} rows are seeded directly (it's a plain V1-baseline table with no
 * JPA entity, per the AI Security module's own JdbcTemplate-only convention) rather than through
 * the full AI Security observation ingestion pipeline, which pulls in dependencies unrelated to
 * what's under test here.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.bom.contribution-backfill.initial-delay-ms=600000"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomDeploymentLinkingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_deployment_linking");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private TenantService tenantService;
    @Autowired private BomIngestionOrchestrator orchestrator;
    @Autowired private AiBomDeclaredResourceRepository declaredResourceRepository;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    private static byte[] aiBomWithOneModel(String name, String version) {
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[{\"type\":\"machine-learning-model\",\"name\":\"" + name
                + "\",\"version\":\"" + version + "\",\"purl\":\"pkg:huggingface/" + name + "@" + version + "\"}]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private void upload(Tenant tenant, String assetIdentifier, byte[] content) throws Exception {
        orchestrator.ingestFromUpload(
                tenant, BomType.AI_BOM, AssetType.APPLICATION, assetIdentifier, assetIdentifier,
                "acme", content, "ai-bom.json", BomSourceSelector.independent());
    }

    /** Mirrors what a real AWS/Azure discovery run would have written into this table. */
    private void seedArtifact(Tenant tenant, UUID artifactId, String name, String modelVersion) {
        Instant now = Instant.now();
        String attributes = modelVersion == null
                ? "{}"
                : "{\"modelVersion\":\"" + modelVersion + "\"}";
        jdbc.update("""
                insert into ai_security_artifacts (
                    id, tenant_id, provider, provider_resource_id, artifact_type, native_kind,
                    name, account_id, region, active, attributes_json, first_observed_at, last_observed_at
                ) values (
                    :id, :tenantId, 'AWS', :providerResourceId, 'AI_MODEL', 'AWS_BEDROCK_MODEL',
                    :name, '123456789012', 'us-east-1', true, cast(:attributes as jsonb), :now, :now
                )
                """,
                Map.of(
                        "id", artifactId,
                        "tenantId", tenant.getId(),
                        "providerResourceId", "arn:aws:bedrock:us-east-1::model/" + artifactId,
                        "name", name,
                        "attributes", attributes,
                        "now", java.sql.Timestamp.from(now)));
    }

    @Test
    void aDeclaredModelIsLinkedToTheSingleMatchingArtifactByNameAndVersion() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "linking-match-" + SEQUENCE.incrementAndGet();
        UUID artifactId = UUID.randomUUID();
        seedArtifact(tenant, artifactId, "llama-3", "3.1");

        upload(tenant, asset, aiBomWithOneModel("llama-3", "3.1"));

        AiBomDeclaredResource declared = onlyDeclaredResourceForNewestSource(tenant);
        assertEquals(AiBomDeploymentState.LINKED, declared.getDeploymentState());
        assertEquals(artifactId, declared.getLinkedArtifactId());
        assertEquals(AiBomLinkMethod.VERSIONED_IDENTIFIER_MATCH, declared.getLinkMethod());
    }

    @Test
    void twoArtifactsSharingANameWithDifferentVersionsMakeTheDeclarationAmbiguous() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "linking-ambiguous-" + SEQUENCE.incrementAndGet();
        seedArtifact(tenant, UUID.randomUUID(), "llama-3", "2.0");
        seedArtifact(tenant, UUID.randomUUID(), "llama-3", "9.9");

        upload(tenant, asset, aiBomWithOneModel("llama-3", "3.1"));

        AiBomDeclaredResource declared = onlyDeclaredResourceForNewestSource(tenant);
        assertEquals(AiBomDeploymentState.UNVERIFIED, declared.getDeploymentState(),
                "neither candidate's version matches the declared one -- must not guess");
        assertNull(declared.getLinkedArtifactId());
    }

    @Test
    void noMatchingArtifactLeavesTheDeclarationUnverified() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "linking-none-" + SEQUENCE.incrementAndGet();

        upload(tenant, asset, aiBomWithOneModel("some-model-nobody-deployed", "1.0"));

        AiBomDeclaredResource declared = onlyDeclaredResourceForNewestSource(tenant);
        assertEquals(AiBomDeploymentState.UNVERIFIED, declared.getDeploymentState());
        assertNull(declared.getLinkedArtifactId());
    }

    /** All three tests upload to the default tenant, so scope to the most recently declared row. */
    private AiBomDeclaredResource onlyDeclaredResourceForNewestSource(Tenant tenant) {
        return declaredResourceRepository.findAll().stream()
                .filter(resource -> tenant.getId().equals(resource.getTenantId()))
                .max(java.util.Comparator.comparing(AiBomDeclaredResource::getFirstDeclaredAt))
                .orElseThrow(() -> new AssertionError("no declared resource found"));
    }
}
