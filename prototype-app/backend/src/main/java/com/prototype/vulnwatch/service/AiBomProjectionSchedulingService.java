package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The single admission decision for whether an AI-BOM source's projection job gets enqueued
 * now, or the source waits (either for the {@code ai.security} entitlement, or for room in the
 * per-tenant projection queue). Used both at ingestion time and by the reconciliation sweep, so
 * "on entitlement enablement, schedule" and "retain overflow for later scheduling" are the same
 * code path re-run under changed circumstances, not two separate mechanisms.
 */
@Service
public class AiBomProjectionSchedulingService {

    private final TenantEntitlementService entitlementService;
    private final TenantSchemaExecutionService tenantExecution;
    private final BomSourceRepository sourceRepository;
    private final IngestionJobRepository ingestionJobRepository;
    private final IngestionJobService ingestionJobService;
    private final int maxQueuedPerTenant;

    public AiBomProjectionSchedulingService(
            TenantEntitlementService entitlementService,
            TenantSchemaExecutionService tenantExecution,
            BomSourceRepository sourceRepository,
            IngestionJobRepository ingestionJobRepository,
            IngestionJobService ingestionJobService,
            @Value("${app.ai-bom.projection.max-queued-per-tenant:100}") int maxQueuedPerTenant) {
        this.entitlementService = entitlementService;
        this.tenantExecution = tenantExecution;
        this.sourceRepository = sourceRepository;
        this.ingestionJobRepository = ingestionJobRepository;
        this.ingestionJobService = ingestionJobService;
        this.maxQueuedPerTenant = maxQueuedPerTenant;
    }

    public void scheduleOrDefer(Tenant tenant, BomSource source) {
        tenantExecution.run(tenant, () -> {
            if (!entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)) {
                source.setState(BomSourceState.HELD_ENTITLEMENT);
                sourceRepository.save(source);
                return null;
            }

            long queuedAndRunning =
                    ingestionJobRepository.countByStatusAndJobType(
                            IngestionJobService.STATUS_QUEUED, IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION)
                    + ingestionJobRepository.countByStatusAndJobType(
                            IngestionJobService.STATUS_RUNNING, IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION);
            if (queuedAndRunning >= maxQueuedPerTenant) {
                source.setState(BomSourceState.DEFERRED);
                sourceRepository.save(source);
                return null;
            }

            source.setState(BomSourceState.ACTIVE);
            sourceRepository.save(source);
            ingestionJobService.enqueueAiGridBomProjectionJob(tenant, source.getId());
            return null;
        });
    }

    /**
     * Re-runs {@link #scheduleOrDefer} for every source still waiting on entitlement or queue
     * room. A source that's still blocked simply gets re-saved into the same state; one that
     * isn't gets activated and enqueued.
     */
    public void reconcileHeldAndDeferredSources(Tenant tenant) {
        tenantExecution.run(tenant, () -> {
            for (BomSourceState state : List.of(BomSourceState.HELD_ENTITLEMENT, BomSourceState.DEFERRED)) {
                for (BomSource source : sourceRepository.findByState(state)) {
                    if (source.getBomType() == BomType.AI_BOM) {
                        scheduleOrDefer(tenant, source);
                    }
                }
            }
            return null;
        });
    }
}
