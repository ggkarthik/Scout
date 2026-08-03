package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@ConditionalOnProperty(name = "app.ai-security.grid.enabled", havingValue = "true", matchIfMissing = true)
public class AiGridPipelineService {
    private final AiGridSnapshotService snapshots;
    private final AiGridOwnershipService ownership;
    private final AiGridSystemService systems;
    private final AiGridAssessmentService assessments;
    private final AiGridReconciliationService reconciliation;
    private final AiGridRunMetricsService metrics;
    private final AiGridReadinessService readiness;
    private final AiGridCoverageService coverage;

    public AiGridPipelineService(AiGridSnapshotService snapshots, AiGridOwnershipService ownership,
                                 AiGridSystemService systems,
                                 AiGridAssessmentService assessments,
                                 AiGridReconciliationService reconciliation,
                                 AiGridRunMetricsService metrics,
                                 AiGridReadinessService readiness,
                                 AiGridCoverageService coverage) {
        this.snapshots = snapshots;
        this.ownership = ownership;
        this.systems = systems;
        this.assessments = assessments;
        this.reconciliation = reconciliation;
        this.metrics = metrics;
        this.readiness = readiness;
        this.coverage = coverage;
    }

    @Transactional
    public void processCompleteScope(Tenant tenant, ObservationEnvelopeV1 envelope) {
        long started = System.nanoTime();
        snapshots.commitScope(tenant, envelope);
        ownership.resolveRun(tenant, envelope.runId());
        systems.deriveForRun(tenant, envelope.runId());
        assessments.evaluateRun(tenant, envelope.runId());
        List<AiGridCoverageService.CoverageItem> runCandidates =
                coverage.expectedCandidates(envelope.runId());
        reconciliation.reconcile(tenant, envelope.runId(), runCandidates);
        UUID epochId = coverage.refreshCurrent(tenant, envelope.runId());
        reconciliation.reconcileCurrent(tenant, epochId, envelope.runId());
        readiness.computeCurrent(tenant, epochId, envelope.runId());
        long durationMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        metrics.recordCompleteScope(tenant, envelope.runId(), envelope.scopeKey(), durationMs, runCandidates);
    }
}
