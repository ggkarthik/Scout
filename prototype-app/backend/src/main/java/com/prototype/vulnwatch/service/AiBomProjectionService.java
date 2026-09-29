package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomProjectionReceipt;
import com.prototype.vulnwatch.domain.AiBomProvenanceFact;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AiBomProjectionReceiptRepository;
import com.prototype.vulnwatch.repo.AiBomProvenanceFactRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * Projects an AI-BOM source's current state into the {@code provenance.ai_bom_present} fact.
 *
 * <p>Idempotent by design: a durable receipt keyed on the source's revision at projection time
 * is what actually prevents double-projection, not the ingestion job's own queued/running
 * dedupe (which only prevents duplicate <em>queued</em> work, not a retry after the real work
 * already finished). Always reads the source's <em>current</em> state rather than trusting
 * anything from the job payload, so a job that sat queued behind a newer upload still ends up
 * projecting the latest revision rather than a stale one.
 */
@Service
public class AiBomProjectionService {

    static final String OPERATION_AI_BOM_PRESENT = "AI_BOM_PRESENT_PROJECTION";
    static final int PROJECTION_VERSION = 1;
    static final String FACT_KEY = "provenance.ai_bom_present";

    private final BomSourceRepository sourceRepository;
    private final BomIngestionRecordRepository recordRepository;
    private final AiBomProvenanceFactRepository provenanceFactRepository;
    private final AiBomProjectionReceiptRepository receiptRepository;
    private final AiBomProjectionBudgetService budgetService;

    public AiBomProjectionService(
            BomSourceRepository sourceRepository,
            BomIngestionRecordRepository recordRepository,
            AiBomProvenanceFactRepository provenanceFactRepository,
            AiBomProjectionReceiptRepository receiptRepository,
            AiBomProjectionBudgetService budgetService) {
        this.sourceRepository = sourceRepository;
        this.recordRepository = recordRepository;
        this.provenanceFactRepository = provenanceFactRepository;
        this.receiptRepository = receiptRepository;
        this.budgetService = budgetService;
    }

    public void project(Tenant tenant, UUID sourceId) {
        BomSource source = sourceRepository.findById(sourceId)
                .orElseThrow(() -> new IllegalArgumentException("BOM source not found: " + sourceId));
        long revision = source.getRevision();

        if (receiptRepository.existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
                tenant.getId(), sourceId, revision, OPERATION_AI_BOM_PRESENT, PROJECTION_VERSION)) {
            return;
        }

        if (source.getCurrentBomId() == null) {
            return;
        }
        BomIngestionRecord record = recordRepository.findById(source.getCurrentBomId())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Current BOM record not found for source: " + sourceId));

        // Checked after the receipt short-circuit above, not before: a job redelivered after
        // the real work already completed must never burn a fresh admission.
        if (budgetService.admit(tenant) == AiBomProjectionBudgetService.Decision.THROTTLED) {
            throw new AiBomProjectionThrottledException(
                    "Daily AI-BOM projection admission budget exhausted for tenant " + tenant.getId());
        }

        Instant now = Instant.now();
        AiBomProvenanceFact fact = provenanceFactRepository
                .findByTenantIdAndAssetIdAndFactKey(tenant.getId(), record.getAssetId(), FACT_KEY)
                .orElseGet(AiBomProvenanceFact::new);
        fact.setTenantId(tenant.getId());
        fact.setAssetId(record.getAssetId());
        fact.setSourceId(sourceId);
        fact.setBomId(record.getId());
        fact.setBomFormat(record.getFormat() == null ? null : record.getFormat().name());
        fact.setSpecVersion(record.getFormatVersion());
        fact.setDocumentIngestedAt(record.getIngestedAt());
        fact.setProjectedAt(now);
        provenanceFactRepository.save(fact);

        AiBomProjectionReceipt receipt = new AiBomProjectionReceipt();
        receipt.setTenantId(tenant.getId());
        receipt.setSourceId(sourceId);
        receipt.setSourceRevision(revision);
        receipt.setOperation(OPERATION_AI_BOM_PRESENT);
        receipt.setCompletedAt(now);
        receiptRepository.save(receipt);
    }
}
