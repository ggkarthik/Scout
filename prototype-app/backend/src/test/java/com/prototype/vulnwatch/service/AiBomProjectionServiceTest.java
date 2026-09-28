package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AiBomProjectionReceipt;
import com.prototype.vulnwatch.domain.AiBomProvenanceFact;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AiBomProjectionReceiptRepository;
import com.prototype.vulnwatch.repo.AiBomProvenanceFactRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/** Unit-level coverage of the projection's idempotency and field mapping, without a database. */
class AiBomProjectionServiceTest {

    private BomSourceRepository sourceRepository;
    private BomIngestionRecordRepository recordRepository;
    private AiBomProvenanceFactRepository provenanceFactRepository;
    private AiBomProjectionReceiptRepository receiptRepository;
    private AiBomProjectionService service;

    private Tenant tenant;
    private UUID sourceId;
    private BomSource source;

    @BeforeEach
    void setUp() {
        sourceRepository = mock(BomSourceRepository.class);
        recordRepository = mock(BomIngestionRecordRepository.class);
        provenanceFactRepository = mock(AiBomProvenanceFactRepository.class);
        receiptRepository = mock(AiBomProjectionReceiptRepository.class);
        service = new AiBomProjectionService(
                sourceRepository, recordRepository, provenanceFactRepository, receiptRepository);

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        sourceId = UUID.randomUUID();
        source = new BomSource();
        source.setId(sourceId);
        ReflectionTestUtils.setField(source, "revision", 3L);
        source.setCurrentBomId(UUID.randomUUID());
        when(sourceRepository.findById(sourceId)).thenReturn(Optional.of(source));
    }

    private BomIngestionRecord record() {
        BomIngestionRecord record = new BomIngestionRecord();
        ReflectionTestUtils.setField(record, "id", UUID.randomUUID());
        record.setAssetId(UUID.randomUUID());
        record.setFormat(SbomFormat.CYCLONEDX);
        record.setFormatVersion("1.5");
        record.setIngestedAt(Instant.now().minusSeconds(60));
        return record;
    }

    @Test
    void anExistingReceiptForTheCurrentRevisionShortCircuitsWithNoWrites() {
        when(receiptRepository.existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
                tenant.getId(), sourceId, 3L, AiBomProjectionService.OPERATION_AI_BOM_PRESENT,
                AiBomProjectionService.PROJECTION_VERSION))
                .thenReturn(true);

        service.project(tenant, sourceId);

        verify(recordRepository, never()).findById(any());
        verify(provenanceFactRepository, never()).save(any());
        verify(receiptRepository, never()).save(any());
    }

    @Test
    void noExistingReceiptWritesBothTheFactAndTheReceiptWithTheRightFields() {
        // Mockito's default answer for an unstubbed boolean-returning method is already false,
        // matching "no receipt exists yet" -- nothing to stub here.
        BomIngestionRecord record = record();
        when(recordRepository.findById(source.getCurrentBomId())).thenReturn(Optional.of(record));
        when(provenanceFactRepository.findByTenantIdAndAssetIdAndFactKey(
                eq(tenant.getId()), eq(record.getAssetId()), eq(AiBomProjectionService.FACT_KEY)))
                .thenReturn(Optional.empty());

        service.project(tenant, sourceId);

        var factCaptor = org.mockito.ArgumentCaptor.forClass(AiBomProvenanceFact.class);
        verify(provenanceFactRepository).save(factCaptor.capture());
        AiBomProvenanceFact fact = factCaptor.getValue();
        assertEquals(record.getAssetId(), fact.getAssetId());
        assertEquals(sourceId, fact.getSourceId());
        assertEquals(record.getId(), fact.getBomId());
        assertEquals("CYCLONEDX", fact.getBomFormat());
        assertEquals("1.5", fact.getSpecVersion());
        assertEquals(record.getIngestedAt(), fact.getDocumentIngestedAt());

        var receiptCaptor = org.mockito.ArgumentCaptor.forClass(AiBomProjectionReceipt.class);
        verify(receiptRepository).save(receiptCaptor.capture());
        AiBomProjectionReceipt receipt = receiptCaptor.getValue();
        assertEquals(sourceId, receipt.getSourceId());
        assertEquals(3L, receipt.getSourceRevision());
        assertEquals(AiBomProjectionService.OPERATION_AI_BOM_PRESENT, receipt.getOperation());
    }

    @Test
    void aSourceWithNoCurrentBomIsANoOp() {
        source.setCurrentBomId(null);

        service.project(tenant, sourceId);

        verify(recordRepository, never()).findById(any());
        verify(provenanceFactRepository, never()).save(any());
        verify(receiptRepository, never()).save(any());
    }

    @Test
    void refreshingAnExistingFactRowUpdatesItInPlaceRatherThanCreatingASecondOne() {
        BomIngestionRecord record = record();
        when(recordRepository.findById(source.getCurrentBomId())).thenReturn(Optional.of(record));
        AiBomProvenanceFact existing = new AiBomProvenanceFact();
        existing.setId(UUID.randomUUID());
        when(provenanceFactRepository.findByTenantIdAndAssetIdAndFactKey(
                eq(tenant.getId()), eq(record.getAssetId()), eq(AiBomProjectionService.FACT_KEY)))
                .thenReturn(Optional.of(existing));

        service.project(tenant, sourceId);

        var factCaptor = org.mockito.ArgumentCaptor.forClass(AiBomProvenanceFact.class);
        verify(provenanceFactRepository, times(1)).save(factCaptor.capture());
        assertEquals(existing.getId(), factCaptor.getValue().getId());
    }
}
