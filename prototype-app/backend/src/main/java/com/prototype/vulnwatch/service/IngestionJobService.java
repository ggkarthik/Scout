package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.dto.IngestionJobPageResponse;
import com.prototype.vulnwatch.dto.IngestionJobResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IngestionJobService {

    public static final String JOB_TYPE_REMOTE_ENDPOINT = "REMOTE_ENDPOINT";
    public static final String JOB_TYPE_GITHUB_REPOSITORY = "GITHUB_REPOSITORY";
    public static final String JOB_TYPE_GITHUB_GHCR = "GITHUB_GHCR";
    public static final String STATUS_QUEUED = "QUEUED";
    public static final String STATUS_RUNNING = "RUNNING";
    public static final String STATUS_SUCCEEDED = "SUCCEEDED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_CANCELLED = "CANCELLED";

    private final IngestionJobRepository ingestionJobRepository;
    private final CredentialEncryptionService credentialEncryptionService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TenantService tenantService;
    private final TenantQuotaService tenantQuotaService;
    private final AuditEventService auditEventService;
    private final IngestionJobMetricsService ingestionJobMetricsService;
    private final ObjectMapper objectMapper;

    public IngestionJobService(
            IngestionJobRepository ingestionJobRepository,
            CredentialEncryptionService credentialEncryptionService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            TenantService tenantService,
            TenantQuotaService tenantQuotaService,
            AuditEventService auditEventService,
            IngestionJobMetricsService ingestionJobMetricsService,
            ObjectMapper objectMapper
    ) {
        this.ingestionJobRepository = ingestionJobRepository;
        this.credentialEncryptionService = credentialEncryptionService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.tenantService = tenantService;
        this.tenantQuotaService = tenantQuotaService;
        this.auditEventService = auditEventService;
        this.ingestionJobMetricsService = ingestionJobMetricsService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public IngestionJobAcceptedResponse enqueueEndpointJob(Tenant tenant, SbomEndpointIngestionRequest request, String requestedBy) {
        BomFetchRequest bomRequest = new BomFetchRequest(
                com.prototype.vulnwatch.domain.BomType.SBOM,
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                request.sourceUrl(),
                request.sourceLabel(),
                null,
                request.authorizationHeader()
        );
        return enqueueBomFetchJob(tenant, bomRequest, requestedBy, "remote-endpoint");
    }

    @Transactional
    public IngestionJobAcceptedResponse enqueueBomFetchJob(Tenant tenant, BomFetchRequest request, String requestedBy) {
        return enqueueBomFetchJob(tenant, request, requestedBy, "bom-fetch");
    }

    private IngestionJobAcceptedResponse enqueueBomFetchJob(Tenant tenant, BomFetchRequest request, String requestedBy, String quotaSource) {
        tenantQuotaService.assertCanCreateSbomIngestionJob(tenant, quotaSource);
        IngestionJobPayloads.EndpointIngestionPayload payload = new IngestionJobPayloads.EndpointIngestionPayload(
                request.bomType(),
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                request.sourceUrl(),
                request.sourceLabel(),
                request.supplier(),
                credentialEncryptionService.encrypt(request.authorizationHeader())
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_REMOTE_ENDPOINT,
                quotaSource,
                request.assetIdentifier(),
                requestedBy,
                payload
        );
    }

    @Transactional
    public IngestionJobAcceptedResponse enqueueGithubRepositoryJob(
            Tenant tenant,
            GithubSbomIngestionRequest request,
            UUID syncRunId,
            UUID sourceId,
            String requestedBy
    ) {
        tenantQuotaService.assertCanCreateSbomIngestionJob(tenant, "github");
        String normalizedRepo = request.repo() == null ? "" : request.repo().trim();
        String assetIdentifier = request.assetIdentifier() == null || request.assetIdentifier().isBlank()
                ? "github:" + normalize(request.owner()) + "/" + normalize(normalizedRepo)
                : request.assetIdentifier();
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = new IngestionJobPayloads.GithubRepositoryIngestionPayload(
                request.owner(),
                request.repo(),
                request.includeAllRepos(),
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                syncRunId,
                sourceId
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_GITHUB_REPOSITORY,
                "github",
                assetIdentifier,
                requestedBy,
                payload
        );
    }

    @Transactional
    public IngestionJobAcceptedResponse enqueueGithubGhcrJob(
            Tenant tenant,
            String owner,
            UUID syncRunId,
            UUID sourceId,
            String requestedBy
    ) {
        tenantQuotaService.assertCanCreateSbomIngestionJob(tenant, "github");
        IngestionJobPayloads.GithubGhcrIngestionPayload payload = new IngestionJobPayloads.GithubGhcrIngestionPayload(
                owner,
                syncRunId,
                sourceId
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_GITHUB_GHCR,
                "github",
                "ghcr:" + normalize(owner),
                requestedBy,
                payload
        );
    }

    @Transactional(readOnly = true)
    public IngestionJobResponse getJob(Tenant tenant, UUID jobId) {
        IngestionJob job = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId)));
        return toResponse(job);
    }

    @Transactional(readOnly = true)
    public IngestionJobPageResponse listJobs(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        Pageable pageable = PageRequest.of(safePage, safeSize);
        Page<IngestionJob> jobs = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findAllByOrderByRequestedAtDescIdDesc(pageable));
        return new IngestionJobPageResponse(
                jobs.getContent().stream().map(this::toResponse).toList(),
                jobs.getNumber(),
                jobs.getSize(),
                jobs.getTotalElements(),
                jobs.getTotalPages()
        );
    }

    @Transactional
    public List<ClaimedJobRef> claimPendingJobs(Tenant tenant, int limit, int maxConcurrentPerTenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            long running = ingestionJobRepository.countByStatusValue(STATUS_RUNNING);
            if (running >= maxConcurrentPerTenant) {
                return List.of();
            }
            int claimLimit = Math.max(0, Math.min(limit, maxConcurrentPerTenant - (int) running));
            if (claimLimit == 0) {
                return List.of();
            }
            List<IngestionJob> jobs = ingestionJobRepository.pollPending(claimLimit);
            Instant now = Instant.now();
            for (IngestionJob job : jobs) {
                job.setStatus(STATUS_RUNNING);
                job.setStartedAt(now);
                job.setAttemptCount(job.getAttemptCount() + 1);
            }
            ingestionJobRepository.saveAll(jobs);
            return jobs.stream()
                    .map(job -> new ClaimedJobRef(tenant.getId(), job.getId()))
                    .toList();
        });
    }

    @Transactional(readOnly = true)
    public IngestionJob loadJob(UUID tenantId, UUID jobId) {
        return tenantSchemaExecutionService.run(tenantId, () -> ingestionJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId)));
    }

    @Transactional
    public void markQueuedForRetry(UUID tenantId, UUID jobId, String failureCode, String failureMessage, Instant visibleAt) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            job.setStatus(STATUS_QUEUED);
            job.setFailureCode(failureCode);
            job.setFailureMessage(failureMessage);
            job.setVisibleAt(visibleAt);
            ingestionJobRepository.save(job);
            return null;
        });
    }

    @Transactional
    public void markFailed(UUID tenantId, UUID jobId, String failureCode, String failureMessage) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            job.setStatus(STATUS_FAILED);
            job.setFailureCode(failureCode);
            job.setFailureMessage(failureMessage);
            job.setCompletedAt(Instant.now());
            ingestionJobRepository.save(job);
            return null;
        });
    }

    @Transactional
    public void markSucceeded(UUID tenantId, UUID jobId, SbomUpload sbomUpload, String resultJson) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            job.setStatus(STATUS_SUCCEEDED);
            job.setFailureCode(null);
            job.setFailureMessage(null);
            job.setCompletedAt(Instant.now());
            job.setSbomUpload(sbomUpload);
            job.setResultJson(resultJson);
            ingestionJobRepository.save(job);
            return null;
        });
    }

    @Transactional
    public int recoverInterruptedRunningJobs() {
        Instant now = Instant.now();
        int recovered = 0;
        for (Tenant tenant : tenantService.listTenants()) {
            List<IngestionJob> stale = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findByStatus(STATUS_RUNNING));
            if (stale.isEmpty()) {
                continue;
            }
            for (IngestionJob job : stale) {
                job.setStatus(STATUS_FAILED);
                job.setFailureCode("WORKER_INTERRUPTED");
                if (job.getFailureMessage() == null || job.getFailureMessage().isBlank()) {
                    job.setFailureMessage("Ingestion job interrupted by service restart");
                }
                if (job.getCompletedAt() == null) {
                    job.setCompletedAt(now);
                }
            }
            tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.saveAll(stale));
            recovered += stale.size();
            for (IngestionJob job : stale) {
                recordFailed(job);
            }
        }
        return recovered;
    }

    public <T> T readPayload(IngestionJob job, Class<T> payloadType) {
        try {
            return objectMapper.readValue(job.getPayloadJson(), payloadType);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to deserialize ingestion payload", ex);
        }
    }

    public String decrypt(String storedValue) {
        return credentialEncryptionService.decrypt(storedValue);
    }

    public String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to serialize ingestion payload", ex);
        }
    }

    public void recordStarted(IngestionJob job) {
        auditEventService.record("ingestion.job.started", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordStarted(job.getSourceType());
        ingestionJobMetricsService.recordEnqueueToStartLatency(job.getSourceType(), job.getRequestedAt(), job.getStartedAt());
    }

    public void recordCompleted(IngestionJob job) {
        auditEventService.record("ingestion.job.completed", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordCompleted(job.getSourceType());
        ingestionJobMetricsService.recordExecutionDuration(job.getSourceType(), job.getStartedAt(), job.getCompletedAt());
    }

    public void recordFailed(IngestionJob job) {
        auditEventService.record("ingestion.job.failed", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordFailed(job.getSourceType());
    }

    public void recordLockRetry(IngestionJob job) {
        auditEventService.record("ingestion.job.lock_retry", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordLockRetry(job.getSourceType());
    }

    private IngestionJobAcceptedResponse enqueueJob(
            Tenant tenant,
            String jobType,
            String sourceType,
            String assetIdentifier,
            String requestedBy,
            Object payload
    ) {
        String normalizedAssetIdentifier = normalize(assetIdentifier);
        String dedupeKey = jobType.toLowerCase(Locale.ROOT) + ":" + normalizedAssetIdentifier;
        Optional<IngestionJob> existing = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findActiveByDedupeKeyForUpdate(dedupeKey));
        if (existing.isPresent()) {
            IngestionJob job = existing.get();
            ingestionJobMetricsService.recordDeduped(sourceType);
            auditEventService.record("ingestion.job.deduped", "ingestion_job", job.getId().toString(), null);
            return new IngestionJobAcceptedResponse(job.getId(), job.getStatus(), "Existing ingestion job already active", true, null);
        }

        IngestionJob newJob = new IngestionJob();
        newJob.setTenant(tenant);
        newJob.setJobType(jobType);
        newJob.setSourceType(sourceType);
        newJob.setAssetIdentifier(assetIdentifier);
        newJob.setRequestedBy(requestedBy);
        newJob.setDedupeKey(dedupeKey);
        newJob.setPayloadJson(toJson(payload));
        newJob.setVisibleAt(Instant.now());

        IngestionJob job;
        try {
            job = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.save(newJob));
        } catch (DataIntegrityViolationException ex) {
            IngestionJob existingJob = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findActiveByDedupeKeyForUpdate(dedupeKey)
                    .orElseThrow(() -> ex));
            ingestionJobMetricsService.recordDeduped(sourceType);
            auditEventService.record("ingestion.job.deduped", "ingestion_job", existingJob.getId().toString(), null);
            return new IngestionJobAcceptedResponse(existingJob.getId(), existingJob.getStatus(), "Existing ingestion job already active", true, null);
        }

        auditEventService.record("ingestion.job.created", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordEnqueued(sourceType);
        return new IngestionJobAcceptedResponse(job.getId(), job.getStatus(), "Ingestion job queued", false, null);
    }

    private IngestionJobResponse toResponse(IngestionJob job) {
        SbomUpload sbomUpload = job.getSbomUpload();
        return new IngestionJobResponse(
                job.getId(),
                job.getJobType(),
                job.getSourceType(),
                job.getAssetIdentifier(),
                job.getStatus(),
                job.getRequestedBy(),
                job.getRequestedAt(),
                job.getStartedAt(),
                job.getCompletedAt(),
                job.getAttemptCount(),
                job.getFailureCode(),
                job.getFailureMessage(),
                sbomUpload == null ? null : sbomUpload.getId(),
                job.getResultJson()
        );
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    public record ClaimedJobRef(UUID tenantId, UUID jobId) {
    }
}
