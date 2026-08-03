package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridExposureService;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.HostFactInput;
import com.prototype.vulnwatch.aisecurity.service.AiGridSystemService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class AiGridR2ExposurePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_r2_exposure");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private NamedParameterJdbcTemplate jdbc;
    @Autowired private AiGridSystemService systems;
    @Autowired private AiGridExposureService exposures;
    @Autowired private AiGridHostContextService hostContext;
    @Autowired private ObjectMapper objectMapper;

    @Test
    void exposureGraduatesDemotesClosesAndReopensWithStableIdentity() {
        Tenant tenant = tenants.createTenant("R2 exposure " + UUID.randomUUID(),
                "r2-exposure-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        UUID agent = UUID.randomUUID();
        UUID knowledgeBase = UUID.randomUUID();
        tenantExecution.run(tenant, () -> {
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, knowledgeBase, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");

            UUID hypothesisRun = seedRun(tenant, agent, knowledgeBase, true, true);
            systems.deriveForRun(tenant, hypothesisRun);
            var hypothesis = exposures.correlateCompleteRun(tenant, hypothesisRun);
            assertEquals(1, hypothesis.hypotheses());
            assertEquals(0, hypothesis.validated());
            UUID exposureId = jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class);
            assertEquals(0, count("select count(*) from findings where finding_kind='AI_EXPOSURE'"));

            addValidatingFacts(tenant, agent, knowledgeBase, Instant.now().plus(1, ChronoUnit.HOURS));
            UUID validatedRun = seedRun(tenant, agent, knowledgeBase, true, false);
            systems.deriveForRun(tenant, validatedRun);
            var validated = exposures.correlateCompleteRun(tenant, validatedRun);
            assertEquals(1, validated.validated());
            assertEquals(1, validated.graduated());
            assertEquals(exposureId, jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));

            jdbc.update("update ai_grid_host_context_facts set valid_until=now()-interval '1 second'", Map.of());
            UUID demotionRun = seedRun(tenant, agent, knowledgeBase, true, true);
            systems.deriveForRun(tenant, demotionRun);
            var demoted = exposures.correlateCompleteRun(tenant, demotionRun);
            assertEquals(1, demoted.demoted());
            assertEquals("EXPOSURE_HYPOTHESIS", jdbc.queryForObject(
                    "select state from ai_grid_exposure_paths where id=:id", Map.of("id", exposureId), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"),
                    "stale evidence demotes the exposure without silently closing its finding");

            UUID closureRun = seedRun(tenant, agent, knowledgeBase, false, true);
            systems.deriveForRun(tenant, closureRun);
            assertEquals(1, exposures.correlateCompleteRun(tenant, closureRun).closed());
            assertEquals("CLOSED", jdbc.queryForObject("select status from ai_grid_exposure_paths where id=:id",
                    Map.of("id", exposureId), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='RESOLVED'"));

            addValidatingFacts(tenant, agent, knowledgeBase, Instant.now().plus(1, ChronoUnit.HOURS));
            UUID recurrenceRun = seedRun(tenant, agent, knowledgeBase, true, false);
            systems.deriveForRun(tenant, recurrenceRun);
            exposures.correlateCompleteRun(tenant, recurrenceRun);
            assertEquals(exposureId, jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));
            assertEquals(4, count("select count(*) from ai_grid_system_revisions"),
                    "returning to an earlier membership set must still produce a new immutable revision");
            return null;
        });
    }

    @Test
    void configurationProxyCannotEnterAValidatingHostPort() {
        Tenant tenant = tenants.createTenant("R2 validation " + UUID.randomUUID(),
                "r2-validation-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID artifact = UUID.randomUUID();
            seedArtifact(tenant, artifact, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            assertThrows(IllegalArgumentException.class, () -> hostContext.upsert(tenant, artifact,
                    hostFact("network.internet_reachability_verified", "CONFIGURATION",
                            "REACHABILITY", Instant.now().plus(1, ChronoUnit.HOURS))));
            return null;
        });
    }

    @Test
    void userMembershipDecisionIsAuditedAndLineageDoesNotTransferFindings() {
        Tenant tenant = tenants.createTenant("R2 lineage " + UUID.randomUUID(),
                "r2-lineage-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID kb = UUID.randomUUID(); UUID extra = UUID.randomUUID();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, kb, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");
            seedArtifact(tenant, extra, "SUPPORTING_RESOURCE", "AWS_S3_BUCKET", "data");
            UUID run = seedRun(tenant, agent, kb, true, false);
            systems.deriveForRun(tenant, run);
            UUID systemId = jdbc.queryForObject("select id from ai_grid_systems", Map.of(), UUID.class);
            int revision = systems.reviseMembership(tenant, systemId, extra, "ACCEPT", "analyst", "Confirmed system member",
                    "SUCCESSOR", java.util.List.of(systemId));
            assertEquals(2, revision);
            assertEquals(1, count("select count(*) from ai_grid_system_membership_decisions where decision='ACCEPT'"));
            assertEquals(1, count("select count(*) from ai_grid_system_lineage_events where event_type='SUCCESSOR'"));
            assertEquals(0, count("select count(*) from finding_subjects where subject_type='AI_SYSTEM'"));
            return null;
        });
    }

    private void addValidatingFacts(Tenant tenant, UUID agent, UUID kb, Instant validUntil) {
        hostContext.upsert(tenant, agent, hostFact("network.internet_reachability_verified", "GRAPH_ANALYSIS", "REACHABILITY", validUntil));
        hostContext.upsert(tenant, agent, hostFact("identity.inadequate_authentication_verified", "GRAPH_ANALYSIS", "IDENTITY", validUntil));
        hostContext.upsert(tenant, kb, hostFact("data.sensitive_access_confirmed", "DSPM", "DATA", validUntil));
    }

    private HostFactInput hostFact(String key, String evidenceClass, String port, Instant validUntil) {
        Instant now = Instant.now().minus(1, ChronoUnit.SECONDS);
        return new HostFactInput(key, objectMapper.valueToTree(true), "KNOWN", "HOST_INTEGRATION",
                evidenceClass, port, "evidence://" + key, now, now, validUntil,
                "APPROVED_HOST_EVIDENCE", "1.0.0", 0.99);
    }

    private UUID seedRun(Tenant tenant, UUID agent, UUID kb, boolean relationship, boolean proxies) {
        UUID runId = UUID.randomUUID(); Instant observed = Instant.now();
        UUID agentManifest = seedManifest(tenant, runId, agent, observed, "agent-" + runId);
        seedManifest(tenant, runId, kb, observed, "kb-" + runId);
        upsertSource(tenant, runId, agent, observed);
        upsertSource(tenant, runId, kb, observed);
        if (relationship) jdbc.update("""
                insert into ai_grid_relationship_snapshots
                    (id,tenant_id,run_id,source_artifact_id,target_artifact_id,relationship_type,
                     observed_at,valid_from)
                values (gen_random_uuid(),:tenantId,:runId,:agent,:kb,'USES_KNOWLEDGE_BASE',:observed,:observed),
                       (gen_random_uuid(),:tenantId,:runId,:kb,:agent,'USES_DATA_SOURCE',:observed,:observed)
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("agent", agent).addValue("kb", kb).addValue("observed", Timestamp.from(observed)));
        if (proxies) {
            seedFact(tenant, runId, agent, agentManifest, "network.public_access_configured", "true", observed);
            seedFact(tenant, runId, agent, agentManifest, "identity.local_auth_enabled_configured", "true", observed);
            seedFact(tenant, runId, agent, agentManifest, "data.source_linked", "true", observed);
        }
        return runId;
    }

    private void seedArtifact(Tenant tenant, UUID id, String type, String nativeKind, String name) {
        jdbc.update("""
                insert into ai_security_artifacts
                    (id,tenant_id,provider,provider_resource_id,artifact_type,native_kind,name,account_id,region,
                     attributes_json,first_observed_at,last_observed_at)
                values (:id,:tenantId,'AWS',:resourceId,:type,:nativeKind,:name,'123456789012','us-east-1',
                        '{}'::jsonb,now(),now())
                """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                .addValue("resourceId", "arn:test:" + id).addValue("type", type)
                .addValue("nativeKind", nativeKind).addValue("name", name));
    }

    private UUID seedManifest(Tenant tenant, UUID runId, UUID artifactId, Instant observed, String seed) {
        UUID bodyId = UUID.randomUUID(); UUID manifestId = UUID.randomUUID();
        jdbc.update("""
                insert into ai_grid_snapshot_bodies
                    (id,tenant_id,content_hash,content_json,byte_size,redaction_profile,first_run_id)
                values (:id,:tenantId,:hash,'{}'::jsonb,2,'STANDARD_V1',:runId)
                """, new MapSqlParameterSource().addValue("id", bodyId).addValue("tenantId", tenant.getId())
                .addValue("hash", String.format("%064x", Math.abs(seed.hashCode()))).addValue("runId", runId));
        jdbc.update("""
                insert into ai_grid_snapshot_manifests
                    (id,tenant_id,run_id,artifact_id,scope_key,body_id,schema_version,observed_at)
                values (:id,:tenantId,:runId,:artifactId,'AWS:test',:bodyId,'1.0.0',:observed)
                """, new MapSqlParameterSource().addValue("id", manifestId).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("artifactId", artifactId).addValue("bodyId", bodyId)
                .addValue("observed", Timestamp.from(observed)));
        return manifestId;
    }

    private void upsertSource(Tenant tenant, UUID runId, UUID artifactId, Instant observed) {
        jdbc.update("""
                insert into ai_security_artifact_sources
                    (id,tenant_id,artifact_id,scope_key,run_id,observed_at,evidence_hash)
                values (gen_random_uuid(),:tenantId,:artifactId,'AWS:test',:runId,:observed,:hash)
                on conflict (tenant_id,artifact_id,scope_key) do update set run_id=excluded.run_id,
                    observed_at=excluded.observed_at,evidence_hash=excluded.evidence_hash
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("artifactId", artifactId)
                .addValue("runId", runId).addValue("observed", Timestamp.from(observed)).addValue("hash", runId.toString()));
    }

    private void seedFact(Tenant tenant, UUID runId, UUID artifactId, UUID manifestId,
                          String key, String value, Instant observed) {
        jdbc.update("""
                insert into ai_grid_facts
                    (id,tenant_id,run_id,artifact_id,snapshot_manifest_id,fact_key,value_type,value_json,state,
                     provenance,evidence_class,source,observed_at,fact_schema_version)
                values (gen_random_uuid(),:tenantId,:runId,:artifactId,:manifestId,:key,'BOOLEAN',cast(:value as jsonb),
                        'KNOWN','PROVIDER_OBSERVED','CONFIGURATION','test',:observed,'1.0.0')
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("artifactId", artifactId).addValue("manifestId", manifestId).addValue("key", key)
                .addValue("value", value).addValue("observed", Timestamp.from(observed)));
    }

    private int count(String sql) { Integer count = jdbc.queryForObject(sql, Map.of(), Integer.class); return count == null ? 0 : count; }
}
