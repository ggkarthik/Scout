package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Drift now means "evidence says this component is here and the projection disagrees", which
 * is only expressible because contributions record the resolved inventory component.
 */
class BomProjectionReconciliationServiceTest {

    private BomIngestionRecordRepository recordRepository;
    private BomSourceRepository sourceRepository;
    private BomComponentContributionRepository contributionRepository;
    private InventoryComponentRepository inventoryComponentRepository;
    private AssetRepository assetRepository;
    private BomProjectionReconciliationService service;

    private Tenant tenant;
    private Asset asset;
    private UUID sourceId;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        TenantService tenantService = mock(TenantService.class);
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        recordRepository = mock(BomIngestionRecordRepository.class);
        sourceRepository = mock(BomSourceRepository.class);
        contributionRepository = mock(BomComponentContributionRepository.class);
        inventoryComponentRepository = mock(InventoryComponentRepository.class);
        assetRepository = mock(AssetRepository.class);
        ObjectProvider<MeterRegistry> meterRegistryProvider = mock(ObjectProvider.class);
        when(meterRegistryProvider.getIfAvailable()).thenReturn(null);

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        asset = new Asset();
        ReflectionTestUtils.setField(asset, "id", UUID.randomUUID());
        asset.setIdentifier("pkg:npm/app");
        sourceId = UUID.randomUUID();

        when(tenantService.listActiveTenants()).thenReturn(List.of(tenant));
        when(tenantSchemaExecutionService.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());

        BomIngestionRecord record = new BomIngestionRecord();
        record.setAssetId(asset.getId());
        record.setStatus(BomStatus.ACTIVE);
        when(recordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE))
                .thenReturn(List.of(record));
        when(assetRepository.findAllById(any())).thenReturn(List.of(asset));

        BomSource source = new BomSource();
        ReflectionTestUtils.setField(source, "id", sourceId);
        source.setAssetId(asset.getId());
        when(sourceRepository.findByAssetId(asset.getId())).thenReturn(List.of(source));

        service = new BomProjectionReconciliationService(
                tenantService, tenantSchemaExecutionService, recordRepository,
                sourceRepository, contributionRepository, inventoryComponentRepository,
                assetRepository, meterRegistryProvider);
    }

    private void supporting(int count) {
        List<BomComponentContribution> contributions = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            BomComponentContribution contribution = new BomComponentContribution();
            contribution.setSourceId(sourceId);
            contribution.setInventoryComponentId(UUID.randomUUID());
            contribution.setContributionState(BomContributionState.SUPPORTED);
            contributions.add(contribution);
        }
        when(contributionRepository.findBySourceIdAndContributionState(
                sourceId, BomContributionState.SUPPORTED)).thenReturn(contributions);
    }

    private int driftCount() {
        return ((AtomicInteger) ReflectionTestUtils.getField(service, "lastDriftCount")).get();
    }

    @Test
    void anAssetWhoseSupportedComponentsAreAllActiveHasNotDrifted() {
        supporting(3);
        when(inventoryComponentRepository.countByIdInAndComponentStatus(
                anyCollection(), any(InventoryComponentStatus.class))).thenReturn(3L);

        service.reconcileProjectionDrift();

        assertEquals(0, driftCount());
    }

    @Test
    void aSupportedComponentThatIsNoLongerActiveIsDrift() {
        supporting(3);
        when(inventoryComponentRepository.countByIdInAndComponentStatus(
                anyCollection(), any(InventoryComponentStatus.class))).thenReturn(2L);

        service.reconcileProjectionDrift();

        assertEquals(1, driftCount());
    }

    // The whole migration window: assets with BOM documents but no contributions yet. The old
    // count comparison flagged these, which would have made the gauge meaningless while the
    // backfill worked through them.
    @Test
    void anAssetAwaitingBackfillIsNotReportedAsDrifted() {
        when(contributionRepository.findBySourceIdAndContributionState(
                sourceId, BomContributionState.SUPPORTED)).thenReturn(List.of());

        service.reconcileProjectionDrift();

        assertEquals(0, driftCount());
    }

    // Several sources sharing an asset legitimately report overlapping components. Counting
    // raw BOM components summed those and double-counted the overlap; counting distinct
    // resolved components does not.
    @Test
    void overlappingClaimsFromTwoSourcesCountAsOneComponent() {
        UUID shared = UUID.randomUUID();
        UUID secondSourceId = UUID.randomUUID();
        BomSource second = new BomSource();
        ReflectionTestUtils.setField(second, "id", secondSourceId);
        second.setAssetId(asset.getId());
        BomSource first = new BomSource();
        ReflectionTestUtils.setField(first, "id", sourceId);
        first.setAssetId(asset.getId());
        when(sourceRepository.findByAssetId(asset.getId())).thenReturn(List.of(first, second));

        BomComponentContribution fromFirst = new BomComponentContribution();
        fromFirst.setSourceId(sourceId);
        fromFirst.setInventoryComponentId(shared);
        fromFirst.setContributionState(BomContributionState.SUPPORTED);
        BomComponentContribution fromSecond = new BomComponentContribution();
        fromSecond.setSourceId(secondSourceId);
        fromSecond.setInventoryComponentId(shared);
        fromSecond.setContributionState(BomContributionState.SUPPORTED);
        when(contributionRepository.findBySourceIdAndContributionState(
                sourceId, BomContributionState.SUPPORTED)).thenReturn(List.of(fromFirst));
        when(contributionRepository.findBySourceIdAndContributionState(
                secondSourceId, BomContributionState.SUPPORTED)).thenReturn(List.of(fromSecond));
        when(inventoryComponentRepository.countByIdInAndComponentStatus(
                anyCollection(), any(InventoryComponentStatus.class))).thenReturn(1L);

        service.reconcileProjectionDrift();

        assertEquals(0, driftCount(), "two sources vouching for one component is not drift");
    }
}
