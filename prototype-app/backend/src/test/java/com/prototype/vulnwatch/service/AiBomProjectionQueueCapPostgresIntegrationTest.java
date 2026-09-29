package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
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
 * End-to-end acceptance for Milestone 2 part 4.5's queue-depth cap and the reconciliation
 * sweep that later picks up deferred sources. Overrides the default 100/tenant cap down to 1.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.bom.contribution-backfill.initial-delay-ms=600000",
        "app.ai-bom.projection.initial-delay-ms=600000",
        "app.ai-bom.projection.reconcile-interval-ms=600000",
        "app.ai-bom.projection.max-queued-per-tenant=1"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomProjectionQueueCapPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_projection_queue_cap");

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
    @Autowired private AiBomProjectionSchedulingService schedulingService;

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

    @Test
    void aSecondSourceIsDeferredUntilTheQueueDrainsAndTheSweepPicksItUp() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();

        BomSource sourceA = upload(tenant, "queuecap-a-" + SEQUENCE.incrementAndGet());
        assertEquals(BomSourceState.ACTIVE, bomSourceRepository.findById(sourceA.getId()).orElseThrow().getState());
        long queuedForA = ingestionJobRepository.findAll().stream()
                .filter(job -> tenant.getId().equals(job.getTenant().getId())
                        && "AI_GRID_BOM_PROJECTION".equals(job.getJobType())
                        && "QUEUED".equals(job.getStatus()))
                .count();
        assertEquals(1, queuedForA, "source A's job must still be queued (worker not run yet)");

        BomSource sourceB = upload(tenant, "queuecap-b-" + SEQUENCE.incrementAndGet());

        BomSource reloadedB = bomSourceRepository.findById(sourceB.getId()).orElseThrow();
        assertEquals(BomSourceState.DEFERRED, reloadedB.getState(),
                "source B must be deferred: the queue already has one job and the cap is 1");
        boolean bHasAJob = ingestionJobRepository.findAll().stream()
                .anyMatch(job -> job.getDedupeKey() != null && job.getDedupeKey().endsWith(sourceB.getId().toString()));
        assertTrue(!bHasAJob, "no job should be created for a deferred source");

        // Drain A's job so the queue has room again, then run the sweep.
        markJobForSourceTerminal(tenant, sourceA.getId());
        schedulingService.reconcileHeldAndDeferredSources(tenant);

        BomSource reconciledB = bomSourceRepository.findById(sourceB.getId()).orElseThrow();
        assertEquals(BomSourceState.ACTIVE, reconciledB.getState(),
                "once the queue has room, the sweep must activate the deferred source");
        boolean bHasAJobNow = ingestionJobRepository.findAll().stream()
                .anyMatch(job -> job.getDedupeKey() != null && job.getDedupeKey().endsWith(sourceB.getId().toString()));
        assertTrue(bHasAJobNow, "the sweep must enqueue the now-activated source's job");
    }

    private void markJobForSourceTerminal(Tenant tenant, UUID sourceId) {
        var job = ingestionJobRepository.findAll().stream()
                .filter(j -> tenant.getId().equals(j.getTenant().getId())
                        && j.getDedupeKey() != null && j.getDedupeKey().endsWith(sourceId.toString()))
                .findFirst()
                .orElseThrow();
        job.setStatus("SUCCEEDED");
        ingestionJobRepository.save(job);
    }
}
