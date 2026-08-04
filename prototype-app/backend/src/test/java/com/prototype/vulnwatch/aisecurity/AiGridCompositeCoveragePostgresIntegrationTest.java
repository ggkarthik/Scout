package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService;
import com.prototype.vulnwatch.aisecurity.service.AiGridReadinessService;
import com.prototype.vulnwatch.aisecurity.service.AiGridReconciliationService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class AiGridCompositeCoveragePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_composite_coverage");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private NamedParameterJdbcTemplate jdbc;
    @Autowired private AiGridCoverageService coverage;
    @Autowired private AiGridReadinessService readiness;
    @Autowired private AiGridReconciliationService reconciliation;

    @Test
    void currentCoverageUnionsProviderScopeHeadsAndHonorsCompleteScopeDeletion() {
        Tenant tenant = tenants.createTenant("Composite coverage " + UUID.randomUUID(),
                "composite-coverage-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        UUID awsRun = UUID.randomUUID();
        UUID azureRun = UUID.randomUUID();

        tenantExecution.run(tenant, () -> {
            seedArtifact(tenant, awsRun, "AWS", "123456789012", "us-east-1", "BEDROCK_AGENTS",
                    "AI_AGENT", "AWS_BEDROCK_AGENT", "aws-agent");
            seedArtifact(tenant, azureRun, "AZURE", "subscription-a", "eastus", "AZURE_RAI_POLICIES",
                    "AI_GUARDRAIL", "AZURE_RAI_POLICIES", "azure-rai");
            UUID epochId = coverage.refreshCurrent(tenant, azureRun);
            reconciliation.reconcileCurrent(tenant, epochId, azureRun);
            readiness.computeCurrent(tenant, epochId, azureRun);
            return null;
        });

        var combined = coverage.coverage(tenant);
        assertEquals(2, combined.authoritativeScopeHeads());
        assertEquals(2, combined.currentArtifacts());
        Set<String> providers = coverage.details(tenant).stream()
                .map(AiGridCoverageService.CoverageItem::provider).collect(Collectors.toSet());
        assertEquals(Set.of("AWS", "AZURE"), providers,
                "a newer Azure run must not remove AWS from tenant current coverage");
        assertTrue(coverage.dimensions(tenant).stream().anyMatch(dimension ->
                "PROVIDER".equals(dimension.dimension()) && "AWS".equals(dimension.value())));
        assertTrue(coverage.dimensions(tenant).stream().anyMatch(dimension ->
                "PROVIDER".equals(dimension.dimension()) && "AZURE".equals(dimension.value())));
        Set<String> dimensions = coverage.dimensions(tenant).stream()
                .map(AiGridCoverageService.CoverageDimension::dimension).collect(Collectors.toSet());
        assertTrue(dimensions.containsAll(Set.of("TECHNOLOGY", "PROVIDER", "FAMILY", "ACCOUNT",
                "ENVIRONMENT", "OWNER", "POLICY", "FRAMEWORK")));
        Set<String> readyPolicies = readiness.latestReadiness(tenant).stream()
                .filter(item -> item.candidateCount() > 0)
                .map(AiGridReadinessService.PolicyReadinessView::policyId).collect(Collectors.toSet());
        assertTrue(readyPolicies.stream().anyMatch(policy -> policy.startsWith("AWS_BEDROCK_")));
        assertTrue(readyPolicies.contains("AZURE_RAI_POLICY_NON_BLOCKING_FILTER"));

        UUID emptyAzureRun = UUID.randomUUID();
        tenantExecution.run(tenant, () -> {
            insertCompleteScope(tenant, emptyAzureRun, "AZURE", "subscription-a", "eastus",
                    "AZURE_RAI_POLICIES");
            UUID epochId = coverage.refreshCurrent(tenant, emptyAzureRun);
            reconciliation.reconcileCurrent(tenant, epochId, emptyAzureRun);
            readiness.computeCurrent(tenant, epochId, emptyAzureRun);
            return null;
        });

        var afterDeletion = coverage.coverage(tenant);
        assertEquals(2, afterDeletion.authoritativeScopeHeads());
        assertEquals(1, afterDeletion.currentArtifacts());
        Set<String> remaining = coverage.details(tenant).stream()
                .map(AiGridCoverageService.CoverageItem::provider).collect(Collectors.toSet());
        assertEquals(Set.of("AWS"), remaining);
        assertFalse(coverage.dimensions(tenant).stream().anyMatch(dimension ->
                "PROVIDER".equals(dimension.dimension()) && "AZURE".equals(dimension.value())));
    }

    private void seedArtifact(Tenant tenant, UUID runId, String provider, String account, String region,
                              String family, String artifactType, String nativeKind, String name) {
        UUID artifactId = UUID.randomUUID();
        UUID bodyId = UUID.randomUUID();
        String scopeKey = provider + ":" + account + ":" + region + ":" + family;
        Instant observedAt = Instant.now();
        insertCompleteScope(tenant, runId, provider, account, region, family);
        var parameters = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("artifactId", artifactId).addValue("bodyId", bodyId)
                .addValue("provider", provider).addValue("account", account).addValue("region", region)
                .addValue("family", family).addValue("artifactType", artifactType)
                .addValue("nativeKind", nativeKind).addValue("name", name)
                .addValue("scopeKey", scopeKey).addValue("observedAt", Timestamp.from(observedAt))
                .addValue("hash", String.format("%064x", Math.abs(name.hashCode())));
        jdbc.update("""
                insert into ai_security_artifacts
                    (id, tenant_id, provider, provider_resource_id, artifact_type, native_kind, name,
                     account_id, region, attributes_json, first_observed_at, last_observed_at)
                values (:artifactId, :tenantId, :provider, :name, :artifactType, :nativeKind, :name,
                        :account, :region, '{"tags":{"environment":"production"}}',
                        :observedAt, :observedAt)
                """, parameters);
        jdbc.update("""
                insert into ai_grid_snapshot_bodies
                    (id, tenant_id, content_hash, content_json, byte_size, redaction_profile, first_run_id)
                values (:bodyId, :tenantId, :hash,
                        jsonb_build_object('artifactType', :artifactType, 'nativeKind', :nativeKind),
                        1, 'STANDARD_V1', :runId)
                """, parameters);
        jdbc.update("""
                insert into ai_grid_snapshot_manifests
                    (id, tenant_id, run_id, artifact_id, scope_key, body_id, schema_version, observed_at)
                values (gen_random_uuid(), :tenantId, :runId, :artifactId, :scopeKey, :bodyId, '1.0.0', :observedAt)
                """, parameters);
    }

    private void insertCompleteScope(Tenant tenant, UUID runId, String provider, String account,
                                     String region, String family) {
        String scopeKey = provider + ":" + account + ":" + region + ":" + family;
        jdbc.update("""
                insert into ai_security_snapshot_scopes
                    (id, tenant_id, run_id, provider, account_id, region, resource_family, scope_key,
                     status, expected_chunks, accepted_chunks, started_at, completed_at)
                values (gen_random_uuid(), :tenantId, :runId, :provider, :account, :region, :family,
                        :scopeKey, 'COMPLETE', 1, 1, now(), now())
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("provider", provider).addValue("account", account).addValue("region", region)
                .addValue("family", family).addValue("scopeKey", scopeKey));
    }
}
