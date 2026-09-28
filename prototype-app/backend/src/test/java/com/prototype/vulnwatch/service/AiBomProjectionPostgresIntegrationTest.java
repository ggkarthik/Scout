package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.AiBomProvenanceFact;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.AiBomProjectionReceiptRepository;
import com.prototype.vulnwatch.repo.AiBomProvenanceFactRepository;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
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
 * End-to-end acceptance for Milestone 2 parts 4.3+4.4: an AI-BOM upload enqueues a real
 * ingestion job, and the scheduled worker actually claims and projects it -- proving the job
 * type is wired into {@code AI_SECURITY_JOB_TYPES} (the handover's own flagged landmine: add it
 * or the job is never claimed, and it fails silently) rather than just the service logic.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.bom.contribution-backfill.initial-delay-ms=600000",
        // The worker stays enabled (so this test can call poll() directly), but its own
        // @Scheduled timer is pushed far into the future so it can't race the test's manual
        // invocations and process a job before an assertion checks it's still QUEUED.
        "app.ai-bom.projection.initial-delay-ms=600000"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomProjectionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_bom_projection");

    private static final AtomicLong SEQUENCE = new AtomicLong();

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private TenantService tenantService;
    @Autowired private BomIngestionOrchestrator orchestrator;
    @Autowired private BomSourceRepository bomSourceRepository;
    @Autowired private AssetRepository assetRepository;
    @Autowired private IngestionJobRepository ingestionJobRepository;
    @Autowired private AiBomProvenanceFactRepository provenanceFactRepository;
    @Autowired private AiBomProjectionReceiptRepository receiptRepository;
    @Autowired private AiBomProjectionWorker worker;

    private static byte[] aiBom(String modelName, String version) {
        String document = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"serialNumber\":\"urn:uuid:" + UUID.randomUUID() + "\",\"version\":1,"
                + "\"components\":[{\"type\":\"machine-learning-model\",\"name\":\"" + modelName
                + "\",\"version\":\"" + version + "\"}]}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private BomSource upload(Tenant tenant, String assetIdentifier, byte[] content, BomSourceSelector selector)
            throws Exception {
        orchestrator.ingestFromUpload(
                tenant, BomType.AI_BOM, AssetType.APPLICATION, assetIdentifier, assetIdentifier,
                "acme", content, "ai-bom.json", selector);
        // Scoped to this call's own asset, not "whichever source currently has the highest
        // revision" -- other tests in this class share the same tenant and can otherwise have
        // already bumped an unrelated source's revision higher than this one's.
        UUID assetId = assetRepository.findByIdentifier(assetIdentifier)
                .orElseThrow(() -> new AssertionError("no asset resolved for " + assetIdentifier))
                .getId();
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
    void anAiBomUploadEnqueuesAndTheWorkerProjectsTheProvenanceFact() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "projection-" + SEQUENCE.incrementAndGet();

        BomSource source = upload(tenant, asset, aiBom("llama-3", "3.1"), BomSourceSelector.independent());

        IngestionJob job = theProjectionJobFor(tenant, source.getId());
        assertEquals("QUEUED", job.getStatus(), "the upload must enqueue a real job, not just call the service directly");

        worker.poll();

        IngestionJob completed = ingestionJobRepository.findById(job.getId()).orElseThrow();
        assertEquals("SUCCEEDED", completed.getStatus());

        List<AiBomProvenanceFact> facts = provenanceFactRepository.findAll();
        AiBomProvenanceFact fact = facts.stream()
                .filter(f -> tenant.getId().equals(f.getTenantId()) && source.getId().equals(f.getSourceId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no provenance fact projected"));
        assertEquals("CYCLONEDX", fact.getBomFormat());
        assertEquals("1.5", fact.getSpecVersion());
        assertTrue(fact.isValueBoolean());

        assertTrue(receiptRepository.existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
                tenant.getId(), source.getId(), source.getRevision(),
                AiBomProjectionService.OPERATION_AI_BOM_PRESENT, AiBomProjectionService.PROJECTION_VERSION));
    }

    @Test
    void replacingTheSourceProducesASecondProjectionKeyedToTheNewRevision() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String asset = "projection-replace-" + SEQUENCE.incrementAndGet();

        BomSource firstVersion = upload(tenant, asset, aiBom("llama-3", "3.1"), BomSourceSelector.independent());
        worker.poll();
        long firstRevision = bomSourceRepository.findById(firstVersion.getId()).orElseThrow().getRevision();

        upload(tenant, asset, aiBom("llama-3", "3.2"),
                new BomSourceSelector(firstVersion.getId(), null, BomSourceCompleteness.PARTIAL, Set.of(), null));
        worker.poll();

        long secondRevision = bomSourceRepository.findById(firstVersion.getId()).orElseThrow().getRevision();
        assertNotEquals(firstRevision, secondRevision, "a replacement must advance the source's revision");

        assertTrue(receiptRepository.existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
                tenant.getId(), firstVersion.getId(), firstRevision,
                AiBomProjectionService.OPERATION_AI_BOM_PRESENT, AiBomProjectionService.PROJECTION_VERSION));
        assertTrue(receiptRepository.existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
                tenant.getId(), firstVersion.getId(), secondRevision,
                AiBomProjectionService.OPERATION_AI_BOM_PRESENT, AiBomProjectionService.PROJECTION_VERSION));

        AiBomProvenanceFact fact = provenanceFactRepository.findAll().stream()
                .filter(f -> tenant.getId().equals(f.getTenantId()) && firstVersion.getId().equals(f.getSourceId()))
                .findFirst()
                .orElseThrow();
        assertEquals("1.5", fact.getSpecVersion());
    }
}
