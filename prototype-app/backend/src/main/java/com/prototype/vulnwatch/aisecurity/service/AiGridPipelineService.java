package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Collection writes commit before policy assessment is dispatched. */
@Service
@ConditionalOnProperty(name="app.ai-security.grid.enabled",havingValue="true",matchIfMissing=true)
public class AiGridPipelineService {
    private final AiGridSnapshotService snapshots;
    private final AiGridAssessmentWorker worker;
    private final AiGridRunMetricsService metrics;
    public AiGridPipelineService(AiGridSnapshotService snapshots,AiGridAssessmentWorker worker,AiGridRunMetricsService metrics) {
        this.snapshots=snapshots; this.worker=worker; this.metrics=metrics;
    }
    @Transactional
    public void processCompleteScope(Tenant tenant,ObservationEnvelopeV1 envelope) {
        long started=System.nanoTime();
        snapshots.commitScope(tenant,envelope);
        metrics.recordCompleteScope(tenant,envelope.runId(),envelope.scopeKey(),
                java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started),java.util.List.of());
        worker.enqueue(tenant,envelope.runId(),Set.of());
    }
}
