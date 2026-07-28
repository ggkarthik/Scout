package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AiSecuritySyncRunFacade {

    public static final String AWS_SYNC_TYPE = "AI_SECURITY_AWS_BEDROCK";
    public static final String AZURE_SYNC_TYPE = "AI_SECURITY_AZURE_DISCOVERY";
    private static final List<String> SYNC_TYPES = List.of(AWS_SYNC_TYPE, AZURE_SYNC_TYPE);
    private final SyncRunRepository repository;

    public AiSecuritySyncRunFacade(SyncRunRepository repository) {
        this.repository = repository;
    }

    public SyncRun start(Tenant tenant) {
        return start(tenant, AWS_SYNC_TYPE);
    }

    public SyncRun start(Tenant tenant, String syncType) {
        if (!SYNC_TYPES.contains(syncType)) {
            throw new IllegalArgumentException("Unsupported AI Security sync type");
        }
        SyncRun run = new SyncRun();
        run.setTenant(tenant);
        run.setSyncType(syncType);
        run.setRunScope("TENANT_AI_SECURITY");
        run.setStatus("running");
        return repository.save(run);
    }

    public SyncRun loadForTenant(UUID tenantId, UUID runId) {
        return repository.findById(runId)
                .filter(run -> run.getTenant() != null && tenantId.equals(run.getTenant().getId()))
                .filter(run -> SYNC_TYPES.contains(run.getSyncType()))
                .orElseThrow(() -> new IllegalArgumentException("AI Security run not found"));
    }

    public List<SyncRun> listForTenant(UUID tenantId) {
        return repository.findByTenant_IdOrderByStartedAtDesc(tenantId).stream()
                .filter(run -> SYNC_TYPES.contains(run.getSyncType()))
                .limit(100)
                .toList();
    }

    public void complete(UUID tenantId, UUID runId, int fetched, int failed, String metadataJson) {
        SyncRun run = loadForTenant(tenantId, runId);
        run.setRecordsFetched(fetched);
        run.setRecordsInserted(fetched);
        run.setRecordsFailed(failed);
        run.setMetadataJson(metadataJson);
        run.setStatus(failed == 0 ? "completed" : "partial");
        run.setCompletedAt(java.time.Instant.now());
        repository.save(run);
    }

    public void fail(UUID tenantId, UUID runId, String safeMessage) {
        SyncRun run = loadForTenant(tenantId, runId);
        run.setStatus("failed");
        run.setRecordsFailed(1);
        run.setErrorMessage(safeMessage);
        run.setCompletedAt(java.time.Instant.now());
        repository.save(run);
    }
}
