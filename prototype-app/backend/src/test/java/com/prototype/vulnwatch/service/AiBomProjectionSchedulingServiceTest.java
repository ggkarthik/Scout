package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit-level coverage of the single admission decision, without a database. */
@ExtendWith(MockitoExtension.class)
class AiBomProjectionSchedulingServiceTest {

    @Mock private TenantEntitlementService entitlementService;
    @Mock private TenantSchemaExecutionService tenantExecution;
    @Mock private BomSourceRepository sourceRepository;
    @Mock private IngestionJobRepository ingestionJobRepository;
    @Mock private IngestionJobService ingestionJobService;

    private Tenant tenant;
    private BomSource source;
    private AiBomProjectionSchedulingService service;

    @BeforeEach
    void setUp() {
        lenient().when(tenantExecution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        source = new BomSource();
        source.setId(UUID.randomUUID());
        source.setBomType(BomType.AI_BOM);

        service = new AiBomProjectionSchedulingService(
                entitlementService, tenantExecution, sourceRepository, ingestionJobRepository,
                ingestionJobService, 100);
    }

    @Test
    void notEntitledHoldsTheSourceRegardlessOfQueueDepthAndNeverEnqueues() {
        when(entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)).thenReturn(false);

        service.scheduleOrDefer(tenant, source);

        assertEquals(BomSourceState.HELD_ENTITLEMENT, source.getState());
        verify(sourceRepository).save(source);
        verify(ingestionJobService, never()).enqueueAiGridBomProjectionJob(any(), any());
        verify(ingestionJobRepository, never()).countByStatusAndJobType(any(), any());
    }

    @Test
    void entitledAndUnderCapActivatesAndEnqueues() {
        when(entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)).thenReturn(true);
        when(ingestionJobRepository.countByStatusAndJobType(
                eq(IngestionJobService.STATUS_QUEUED), eq(IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION)))
                .thenReturn(0L);
        when(ingestionJobRepository.countByStatusAndJobType(
                eq(IngestionJobService.STATUS_RUNNING), eq(IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION)))
                .thenReturn(0L);

        service.scheduleOrDefer(tenant, source);

        assertEquals(BomSourceState.ACTIVE, source.getState());
        verify(ingestionJobService).enqueueAiGridBomProjectionJob(tenant, source.getId());
    }

    @Test
    void entitledButAtCapDefersWithoutEnqueuing() {
        AiBomProjectionSchedulingService cappedService = new AiBomProjectionSchedulingService(
                entitlementService, tenantExecution, sourceRepository, ingestionJobRepository,
                ingestionJobService, 1);
        when(entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)).thenReturn(true);
        when(ingestionJobRepository.countByStatusAndJobType(
                eq(IngestionJobService.STATUS_QUEUED), eq(IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION)))
                .thenReturn(1L);
        when(ingestionJobRepository.countByStatusAndJobType(
                eq(IngestionJobService.STATUS_RUNNING), eq(IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION)))
                .thenReturn(0L);

        cappedService.scheduleOrDefer(tenant, source);

        assertEquals(BomSourceState.DEFERRED, source.getState());
        verify(ingestionJobService, never()).enqueueAiGridBomProjectionJob(any(), any());
    }

    @Test
    void theSweepReEvaluatesBothHeldAndDeferredSourcesThroughTheSameDecision() {
        BomSource held = new BomSource();
        held.setId(UUID.randomUUID());
        held.setBomType(BomType.AI_BOM);
        BomSource deferred = new BomSource();
        deferred.setId(UUID.randomUUID());
        deferred.setBomType(BomType.AI_BOM);
        when(sourceRepository.findByState(BomSourceState.HELD_ENTITLEMENT)).thenReturn(List.of(held));
        when(sourceRepository.findByState(BomSourceState.DEFERRED)).thenReturn(List.of(deferred));
        // Still not entitled: both should simply be re-saved in the same held state.
        when(entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)).thenReturn(false);

        service.reconcileHeldAndDeferredSources(tenant);

        assertEquals(BomSourceState.HELD_ENTITLEMENT, held.getState());
        assertEquals(BomSourceState.HELD_ENTITLEMENT, deferred.getState());
        verify(sourceRepository).save(held);
        verify(sourceRepository).save(deferred);
        verify(ingestionJobService, never()).enqueueAiGridBomProjectionJob(any(), any());
    }

    @Test
    void theSweepSkipsNonAiBomSources() {
        BomSource notAiBom = new BomSource();
        notAiBom.setId(UUID.randomUUID());
        notAiBom.setBomType(BomType.SBOM);
        when(sourceRepository.findByState(BomSourceState.HELD_ENTITLEMENT)).thenReturn(List.of(notAiBom));
        when(sourceRepository.findByState(BomSourceState.DEFERRED)).thenReturn(List.of());

        service.reconcileHeldAndDeferredSources(tenant);

        verify(sourceRepository, never()).save(notAiBom);
        verify(entitlementService, never()).isEnabled(any(), any());
    }
}
