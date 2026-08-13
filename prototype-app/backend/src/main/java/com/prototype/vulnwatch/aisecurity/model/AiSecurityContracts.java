package com.prototype.vulnwatch.aisecurity.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class AiSecurityContracts {
    private AiSecurityContracts() {
    }

    public enum ScopeStatus {
        COMPLETE,
        PARTIAL,
        FAILED,
        UNSUPPORTED
    }

    public enum EvaluationOutcome {
        PASS,
        FAIL,
        NO_DECISION,
        NOT_APPLICABLE
    }

    public enum FindingStatus {
        OPEN,
        RESOLVED,
        SUPPRESSED_BY_POLICY
    }

    public enum ReviewDisposition {
        UNREVIEWED,
        CONFIRMED,
        FALSE_POSITIVE,
        NEEDS_INVESTIGATION
    }

    public record ObservationEnvelopeV1(
            String contractVersion,
            UUID runId,
            UUID connectorId,
            UUID tenantId,
            String provider,
            String providerTenantId,
            String accountId,
            String region,
            String resourceFamily,
            String scopeKey,
            int chunkSequence,
            int expectedChunks,
            String idempotencyKey,
            String contentHash,
            Instant observedAt,
            ScopeStatus completionStatus,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships,
            List<Diagnostic> diagnostics
    ) {
        public ObservationEnvelopeV1(
                String contractVersion,
                UUID runId,
                UUID connectorId,
                UUID tenantId,
                String provider,
                String accountId,
                String region,
                String resourceFamily,
                String scopeKey,
                int chunkSequence,
                int expectedChunks,
                String idempotencyKey,
                String contentHash,
                Instant observedAt,
                ScopeStatus completionStatus,
                List<ArtifactObservation> artifacts,
                List<RelationshipObservation> relationships,
                List<Diagnostic> diagnostics
        ) {
            this(
                    contractVersion,
                    runId,
                    connectorId,
                    tenantId,
                    provider,
                    null,
                    accountId,
                    region,
                    resourceFamily,
                    scopeKey,
                    chunkSequence,
                    expectedChunks,
                    idempotencyKey,
                    contentHash,
                    observedAt,
                    completionStatus,
                    artifacts,
                    relationships,
                    diagnostics);
        }
    }

    public record ArtifactObservation(
            String providerResourceId,
            String artifactType,
            String nativeKind,
            String name,
            Map<String, Object> attributes,
            String piiScanStatus,
            String piiSource,
            List<String> piiInfoTypes,
            int piiFindingCount,
            Instant piiLastScannedAt
    ) {
        /** No PII lookup applies to this artifact (it has no linked storage to check). */
        public ArtifactObservation(
                String providerResourceId,
                String artifactType,
                String nativeKind,
                String name,
                Map<String, Object> attributes
        ) {
            this(providerResourceId, artifactType, nativeKind, name, attributes,
                    "NOT_APPLICABLE", null, List.of(), 0, null);
        }
    }

    public record RelationshipObservation(
            String sourceProviderResourceId,
            String targetProviderResourceId,
            String relationshipType,
            Map<String, Object> attributes
    ) {
    }

    public record Diagnostic(
            String code,
            String message,
            boolean retryable,
            List<String> missingPermissions,
            String correlationId
    ) {
    }

    public record IngestionResult(
            boolean duplicate,
            ScopeStatus scopeStatus,
            int acceptedChunks,
            int expectedChunks,
            List<Diagnostic> diagnostics
    ) {
    }
}
