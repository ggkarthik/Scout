package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.AwsResourceIngestionService.IngestionResult;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

@Service
public class AwsDiscoverySyncService {

    public static final String SYNC_TYPE_AWS_DISCOVERY = "AWS_DISCOVERY";
    private static final Logger LOG = LoggerFactory.getLogger(AwsDiscoverySyncService.class);

    private final AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    private final AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    private final AwsDiscoveryConfigService awsDiscoveryConfigService;
    private final AwsDiscoveryTargetService awsDiscoveryTargetService;
    private final AwsDiscoveryClient awsDiscoveryClient;
    private final AwsResourceIngestionService awsResourceIngestionService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;
    private final TaskExecutor integrationQueueExecutor;
    private final TransactionTemplate transactionTemplate;
    private final CredentialEncryptionService credentialEncryptionService;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public AwsDiscoverySyncService(
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository,
            AwsDiscoveryTargetRepository awsDiscoveryTargetRepository,
            AwsDiscoveryConfigService awsDiscoveryConfigService,
            AwsDiscoveryTargetService awsDiscoveryTargetService,
            AwsDiscoveryClient awsDiscoveryClient,
            AwsResourceIngestionService awsResourceIngestionService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper,
            @Qualifier("integrationQueueExecutor") TaskExecutor integrationQueueExecutor,
            TransactionTemplate transactionTemplate,
            CredentialEncryptionService credentialEncryptionService,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.awsDiscoveryConfigRepository = awsDiscoveryConfigRepository;
        this.awsDiscoveryTargetRepository = awsDiscoveryTargetRepository;
        this.awsDiscoveryConfigService = awsDiscoveryConfigService;
        this.awsDiscoveryTargetService = awsDiscoveryTargetService;
        this.awsDiscoveryClient = awsDiscoveryClient;
        this.awsResourceIngestionService = awsResourceIngestionService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
        this.integrationQueueExecutor = integrationQueueExecutor;
        this.transactionTemplate = transactionTemplate;
        this.credentialEncryptionService = credentialEncryptionService;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public SyncTriggerResponse trigger() {
        Tenant tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = transactionTemplate.execute(status -> claimManualRun(tenant));
        if (!claimed.reusedActiveRun()) {
            integrationQueueExecutor.execute(() -> executeRun(tenant.getId(), claimed.configId(), claimed.runId(), "manual", null));
            return new SyncTriggerResponse(claimed.runId(), "queued", "AWS Cloud Discovery sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "AWS Cloud Discovery sync is already queued or running");
    }

    public SyncTriggerResponse triggerTarget(Tenant tenant, UUID targetId) {
        AwsDiscoveryTarget target = awsDiscoveryTargetService.requireTarget(tenant, targetId);
        ClaimedRun claimed = transactionTemplate.execute(status -> claimRunForConfig(target.getConfig(), "manual-target", true));
        if (!claimed.reusedActiveRun()) {
            integrationQueueExecutor.execute(() -> executeRun(tenant.getId(), claimed.configId(), claimed.runId(), "manual-target", targetId));
            return new SyncTriggerResponse(claimed.runId(), "queued", "AWS Cloud Discovery target sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "AWS Cloud Discovery sync is already queued or running");
    }

    @Scheduled(cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        List<ConfigRef> configs = new ArrayList<>();
        for (Tenant tenant : tenantService.listTenants()) {
            tenantSchemaExecutionService.run(tenant, () -> {
                awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                        .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                        .ifPresent(config -> configs.add(new ConfigRef(config.getId(), tenant.getId())));
                return null;
            });
        }
        for (ConfigRef configRef : configs) {
            ClaimedRun claimed = tenantSchemaExecutionService.run(configRef.tenantId(), () -> {
                AwsDiscoveryConfig config = awsDiscoveryConfigRepository.findById(configRef.configId()).orElse(null);
                return transactionTemplate.execute(status -> config == null ? null : claimScheduledRun(config));
            });
            if (claimed == null) {
                continue;
            }
            integrationQueueExecutor.execute(() -> executeRun(configRef.tenantId(), claimed.configId(), claimed.runId(), "scheduled", null));
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun() {
        return !syncRunRepository.findActiveRunsBySyncType(SYNC_TYPE_AWS_DISCOVERY, List.of("queued", "running")).isEmpty();
    }

    // ── Run claiming ───────────────────────────────────────────────────────────────────────────

    private ClaimedRun claimManualRun(Tenant tenant) {
        AwsDiscoveryConfig config = awsDiscoveryConfigService.findConfig(tenant)
                .filter(this::isConfigured)
                .orElseThrow(() -> new IllegalStateException("AWS Cloud Discovery connector is not configured"));
        if (!config.isEnabled()) {
            throw new IllegalStateException("AWS Cloud Discovery connector is disabled");
        }
        return claimRunForConfig(config, "manual", true);
    }

    private ClaimedRun claimScheduledRun(AwsDiscoveryConfig config) {
        if (!isConfigured(config) || !config.isEnabled() || !config.isAutoSyncEnabled() || !isDue(config)) {
            return null;
        }
        return claimRunForConfig(config, "scheduled", false);
    }

    private ClaimedRun claimRunForConfig(AwsDiscoveryConfig config, String triggerMode, boolean allowReuseActiveRun) {
        UUID tenantId = config.getTenant().getId();
        Optional<SyncRun> active = syncRunRepository.findActiveRunsBySyncType(
                SYNC_TYPE_AWS_DISCOVERY,
                List.of("queued", "running")
        ).stream().findFirst();
        if (active.isPresent()) {
            if (!allowReuseActiveRun) {
                return null;
            }
            return new ClaimedRun(config.getId(), active.get().getId(), true);
        }

        List<String> regions = parseRegions(config.getRegionsJson());
        List<String> resourceTypes = parseResourceTypes(config.getResourceTypesJson());

        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(SYNC_TYPE_AWS_DISCOVERY);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"),
                "regions", regions,
                "resourceTypes", resourceTypes
        )));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(AwsDiscoveryConfig config) {
        SyncRun latest = syncRunRepository
                .findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc(SYNC_TYPE_AWS_DISCOVERY)
                .orElse(null);
        if (latest == null) {
            return true;
        }
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) {
            return true;
        }
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(5, config.getIntervalMinutes());
        return Duration.between(reference, Instant.now()).toMinutes() >= minutes;
    }

    // ── Execution ──────────────────────────────────────────────────────────────────────────────

    private void executeRun(UUID tenantId, UUID configId, UUID runId, String triggerMode, UUID onlyTargetId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            Instant runStartTime = Instant.now();
            markRunRunning(runId, triggerMode);
            try {
                AwsDiscoveryConfig config = awsDiscoveryConfigRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("AWS Discovery config not found: " + configId));
                awsDiscoveryTargetService.ensureLegacyTarget(config);

                LOG.info("AWS Discovery sync run {} starting (trigger={})", runId, triggerMode);

                List<AwsDiscoveryTarget> targets = resolveTargets(config, onlyTargetId);
                if (targets.isEmpty()) {
                    targets = List.of(legacyVirtualTarget(config));
                }

                int totalFetched = 0;
                int recordsFailed = 0;
                int assetsUpserted = 0;
                int componentsCreated = 0;
                int componentsUpdated = 0;
                int assetsMarkedInactive = 0;
                List<Map<String, Object>> targetResults = new ArrayList<>();

                for (AwsDiscoveryTarget target : targets) {
                    TargetRunResult targetResult = executeTarget(config, target, runId, triggerMode, runStartTime);
                    totalFetched += targetResult.recordsFetched();
                    recordsFailed += targetResult.failed() ? 1 : 0;
                    assetsUpserted += targetResult.ingestionResult().assetsUpserted();
                    componentsCreated += targetResult.ingestionResult().inventoryComponentsCreated();
                    componentsUpdated += targetResult.ingestionResult().inventoryComponentsUpdated();
                    assetsMarkedInactive += targetResult.ingestionResult().assetsMarkedInactive();
                    targetResults.add(targetResult.metadata());
                    updateRunProgress(runId, totalFetched, "ingesting-targets", triggerMode, config, targetResults);
                }

                completeRun(
                        configId,
                        runId,
                        new IngestionResult(assetsUpserted, componentsCreated, componentsUpdated, assetsMarkedInactive),
                        totalFetched,
                        recordsFailed,
                        triggerMode,
                        config,
                        targetResults
                );
            } catch (Exception e) {
                LOG.error("AWS Discovery sync run {} failed: {}", runId, e.getMessage(), e);
                failRun(runId, e.getMessage(), triggerMode);
            }
            return null;
        });
    }

    private TargetRunResult executeTarget(
            AwsDiscoveryConfig config,
            AwsDiscoveryTarget target,
            UUID runId,
            String triggerMode,
            Instant runStartTime
    ) {
        String accountId = defaultIfBlank(target.getAccountId(), defaultIfBlank(config.getAwsAccountId(), ""));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("targetId", target.getId());
        metadata.put("accountId", defaultIfBlank(accountId, "unknown"));
        metadata.put("accountName", defaultIfBlank(target.getAccountName(), "AWS Account"));
        try {
            AwsDiscoveryConfig runtimeConfig = configWithDecryptedCredential(config);
            AwsCredentialsProvider creds = target.getId() == null
                    ? AwsCredentialProvider.from(runtimeConfig)
                    : AwsCredentialProvider.from(runtimeConfig, target);
            List<String> regions = parseRegions(defaultIfBlank(target.getRegionsJson(), config.getRegionsJson()));
            List<String> resourceTypes = parseResourceTypes(defaultIfBlank(target.getResourceTypesJson(), config.getResourceTypesJson()));
            List<AwsResourceRecord> allRecords = fetchTargetRecords(creds, regions);

            LOG.info("AWS Discovery run {} target {} fetched {} records", runId, accountId, allRecords.size());
            IngestionResult result = awsResourceIngestionService.ingestAll(
                    allRecords, config, config.getTenant(), runStartTime, accountId);

            List<AwsResourceRecord> ec2Records = allRecords.stream()
                    .filter(r -> "EC2".equalsIgnoreCase(r.resourceType()))
                    .toList();
            if (!ec2Records.isEmpty()) {
                awsResourceIngestionService.ingestEc2SsmPackages(
                        ec2Records, creds, regions, config.getTenant(), accountId);
            }

            Instant completedAt = Instant.now();
            metadata.put("status", "completed");
            metadata.put("recordsFetched", allRecords.size());
            metadata.put("assetsUpserted", result.assetsUpserted());
            metadata.put("inventoryComponentsCreated", result.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", result.inventoryComponentsUpdated());
            metadata.put("assetsMarkedInactive", result.assetsMarkedInactive());
            if (target.getId() != null) {
                transactionTemplate.executeWithoutResult(status -> {
                    awsDiscoveryTargetRepository.findById(target.getId()).ifPresent(existing -> {
                        if (hasText(accountId)) existing.setAccountId(accountId);
                        existing.setLastSyncAt(completedAt);
                        existing.touch();
                        awsDiscoveryTargetRepository.save(existing);
                    });
                });
            }
            return new TargetRunResult(allRecords.size(), false, result, metadata);
        } catch (Exception e) {
            LOG.warn("AWS Discovery run {} target {} failed: {}", runId, accountId, e.getMessage(), e);
            metadata.put("status", "failed");
            metadata.put("error", e.getMessage());
            return new TargetRunResult(0, true, new IngestionResult(0, 0, 0, 0), metadata);
        }
    }

    private List<AwsResourceRecord> fetchTargetRecords(
            AwsCredentialsProvider creds,
            List<String> regions
    ) {
        try {
            return awsDiscoveryClient.fetchEc2Instances(creds, regions);
        } catch (Exception e) {
            LOG.warn("AWS Discovery: error fetching EC2 resources: {}", e.getMessage(), e);
            return List.of();
        }
    }

    // ── Run lifecycle state transitions ───────────────────────────────────────────────────────

    private void markRunRunning(UUID runId, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("running");
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "running",
                    "sourceSystem", "aws"
            )));
            syncRunRepository.save(run);
        });
    }

    private void updateRunProgress(
            UUID runId,
            int recordsFetched,
            String stage,
            String triggerMode,
            AwsDiscoveryConfig config,
            List<Map<String, Object>> targetResults
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setRecordsFetched(recordsFetched);
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "sourceSystem", "aws",
                    "awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"),
                    "stage", stage,
                    "recordsFetched", recordsFetched,
                    "targets", targetResults
            )));
            syncRunRepository.save(run);
        });
    }

    private void completeRun(
            UUID configId,
            UUID runId,
            IngestionResult result,
            int fetched,
            int failedTargets,
            String triggerMode,
            AwsDiscoveryConfig config,
            List<Map<String, Object>> targetResults
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus(failedTargets > 0 ? "completed_with_errors" : "completed");
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(result.assetsUpserted() + result.inventoryComponentsCreated());
            run.setRecordsUpdated(result.inventoryComponentsUpdated());
            run.setRecordsFailed(failedTargets);
            run.setErrorMessage(failedTargets > 0 ? failedTargets + " AWS discovery target(s) failed" : null);
            run.setCompletedAt(Instant.now());

            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", "aws");
            metadata.put("awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"));
            metadata.put("assetsUpserted", result.assetsUpserted());
            metadata.put("inventoryComponentsCreated", result.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", result.inventoryComponentsUpdated());
            metadata.put("assetsMarkedInactive", result.assetsMarkedInactive());
            metadata.put("totalRecordsFetched", fetched);
            metadata.put("failedTargets", failedTargets);
            metadata.put("targets", targetResults);
            run.setMetadataJson(toJson(metadata));

            syncRunRepository.save(run);
            awsDiscoveryConfigRepository.findById(configId).ifPresent(cfg -> {
                cfg.setLastSyncAt(Instant.now());
                awsDiscoveryConfigRepository.save(cfg);
            });
        });
    }

    private void failRun(UUID runId, String errorMessage, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("failed");
            run.setRecordsFailed(Math.max(1, run.getRecordsFailed()));
            run.setErrorMessage(errorMessage);
            run.setCompletedAt(Instant.now());
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "failed",
                    "sourceSystem", "aws"
            )));
            syncRunRepository.save(run);
        });
    }

    // ── Utilities ──────────────────────────────────────────────────────────────────────────────

    private boolean isConfigured(AwsDiscoveryConfig config) {
        if (config == null || config.getTenant() == null) return false;
        return switch (config.getAuthType() == null ? com.prototype.vulnwatch.domain.AwsAuthType.INSTANCE_METADATA : config.getAuthType()) {
            case INSTANCE_METADATA -> true;
            case ACCESS_KEY -> hasText(config.getAccessKeyId()) && hasText(config.getCredentialSecret());
            case CROSS_ACCOUNT_ROLE -> hasText(config.getCrossAccountRoleArn())
                    || awsDiscoveryTargetRepository.countByConfig(config) > 0;
        };
    }

    private AwsDiscoveryConfig configWithDecryptedCredential(AwsDiscoveryConfig config) {
        if (config == null || !hasText(config.getCredentialSecret())) {
            return config;
        }
        AwsDiscoveryConfig runtimeConfig = new AwsDiscoveryConfig();
        runtimeConfig.setTenant(config.getTenant());
        runtimeConfig.setSourceSystem(config.getSourceSystem());
        runtimeConfig.setAuthType(config.getAuthType());
        runtimeConfig.setAccessKeyId(config.getAccessKeyId());
        runtimeConfig.setCredentialSecret(credentialEncryptionService.decrypt(config.getCredentialSecret()));
        runtimeConfig.setCrossAccountRoleArn(config.getCrossAccountRoleArn());
        runtimeConfig.setExternalId(config.getExternalId());
        runtimeConfig.setAwsAccountId(config.getAwsAccountId());
        runtimeConfig.setRegionsJson(config.getRegionsJson());
        runtimeConfig.setResourceTypesJson(config.getResourceTypesJson());
        runtimeConfig.setEnabled(config.isEnabled());
        runtimeConfig.setAutoSyncEnabled(config.isAutoSyncEnabled());
        runtimeConfig.setIntervalMinutes(config.getIntervalMinutes());
        return runtimeConfig;
    }

    private List<AwsDiscoveryTarget> resolveTargets(AwsDiscoveryConfig config, UUID onlyTargetId) {
        if (onlyTargetId != null) {
            return awsDiscoveryTargetRepository.findById(onlyTargetId)
                    .filter(target -> target.getConfig() != null && config.getId().equals(target.getConfig().getId()))
                    .map(List::of)
                    .orElse(List.of());
        }
        return awsDiscoveryTargetRepository.findByConfigAndEnabledTrueOrderByAccountNameAscAccountIdAsc(config);
    }

    private AwsDiscoveryTarget legacyVirtualTarget(AwsDiscoveryConfig config) {
        AwsDiscoveryTarget target = new AwsDiscoveryTarget();
        target.setTenant(config.getTenant());
        target.setConfig(config);
        target.setAccountId(config.getAwsAccountId());
        target.setAccountName(hasText(config.getAwsAccountId()) ? "AWS Account " + config.getAwsAccountId() : "AWS Account");
        target.setRoleArn(config.getCrossAccountRoleArn());
        target.setExternalId(config.getExternalId());
        target.setEnabled(config.isEnabled());
        target.setRegionsJson(config.getRegionsJson());
        target.setResourceTypesJson(config.getResourceTypesJson());
        return target;
    }

    private List<String> parseRegions(String regionsJson) {
        if (!hasText(regionsJson)) return List.of("us-east-1");
        try {
            return objectMapper.readValue(regionsJson, new TypeReference<>() {});
        } catch (Exception e) {
            return List.of("us-east-1");
        }
    }

    private List<String> parseResourceTypes(String resourceTypesJson) {
        return List.of("EC2");
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ClaimedRun(
            UUID configId,
            UUID runId,
            boolean reusedActiveRun
    ) {}

    private record ConfigRef(UUID configId, UUID tenantId) {}

    private record TargetRunResult(
            int recordsFetched,
            boolean failed,
            IngestionResult ingestionResult,
            Map<String, Object> metadata
    ) {}
}
