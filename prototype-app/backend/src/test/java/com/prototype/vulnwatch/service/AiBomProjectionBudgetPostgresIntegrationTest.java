package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.AiBomProvenanceFactRepository;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
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
 * End-to-end acceptance for Milestone 2 part 4.5's daily admission budget. Overrides the
 * default 100/day limit down to 1 so the throttle path is reachable without 100 real uploads.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.bom.contribution-backfill.initial-delay-ms=600000",
        "app.ai-bom.projection.initial-delay-ms=600000",
        "app.ai-bom.projection.reconcile-interval-ms=600000",
        "app.ai-bom.projection.daily-admission-limit=1"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomProjectionBudgetPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_projection_budget");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private TenantService tenantService;
    @Autowired private BomIngestionOrchestrator orchestrator;
    @Autowired private AssetRepository assetRepository;
    @Autowired private BomSourceRepository bomSourceRepository;
    @Autowired private IngestionJobRepository ingestionJobRepository;
    @Autowired private AiBomProvenanceFactRepository provenanceFactRepository;
    @Autowired private AiBomProjectionWorker worker;

    private static byte[] aiBom(String modelName, String version) {
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[{\"type\":\"machine-learning-model\",\"name\":\"" + modelName
                + "\",\"version\":\"" + version + "\"}]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private BomSource upload(Tenant tenant, String assetIdentifier) throws Exception {
        orchestrator.ingestFromUpload(
                tenant, BomType.AI_BOM, AssetType.APPLICATION, assetIdentifier, assetIdentifier,
                "acme", aiBom("llama-3", "3.1"), "ai-bom.json", BomSourceSelector.independent());
        UUID assetId = assetRepository.findByIdentifier(assetIdentifier).orElseThrow().getId();
        return bomSourceRepository.findAll().stream()
                .filter(source -> tenant.getId().equals(source.getTenantId())
                        && source.getBomType() == BomType.AI_BOM
                        && assetId.equals(source.getAssetId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no AI_BOM source created for " + assetIdentifier));
    }

    private IngestionJob theProjectionJobFor(Tenant tenant, UUID sourceId) {
        return ingestionJobRepository.findAll().stream()
                .filter(job -> tenant.getId().equals(job.getTenant().getId())
                        && "AI_GRID_BOM_PROJECTION".equals(job.getJobType())
                        && job.getDedupeKey() != null
                        && job.getDedupeKey().endsWith(sourceId.toString()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no projection job found for source " + sourceId));
    }

    @Test
    void aSecondIndependentSourceIsThrottledOnceTheDailyLimitIsReached() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();

        BomSource first = upload(tenant, "budget-first-" + SEQUENCE.incrementAndGet());
        worker.poll();
        assertEquals("SUCCEEDED", theProjectionJobFor(tenant, first.getId()).getStatus());
        assertEquals(1, provenanceFactRepository.findAll().stream()
                .filter(f -> tenant.getId().equals(f.getTenantId())).count());

        BomSource second = upload(tenant, "budget-second-" + SEQUENCE.incrementAndGet());
        worker.poll();

        IngestionJob secondJob = theProjectionJobFor(tenant, second.getId());
        assertEquals("QUEUED", secondJob.getStatus(),
                "the second source's job must be requeued (throttled), not failed or succeeded");
        assertTrue(secondJob.getVisibleAt().isAfter(java.time.Instant.now()),
                "a throttled job's visible_at must move into the future");
        assertEquals("DAILY_BUDGET_EXCEEDED", secondJob.getFailureCode());
    }
}
