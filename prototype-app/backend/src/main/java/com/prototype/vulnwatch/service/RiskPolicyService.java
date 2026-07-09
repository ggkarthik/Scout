package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.RiskPolicyPresets;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import java.util.UUID;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class RiskPolicyService {

    private final RiskPolicyRepository riskPolicyRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final ObjectProvider<FindingDeltaQueueService> findingDeltaQueueServiceProvider;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate readTransactionTemplate;
    private final TransactionTemplate writeTransactionTemplate;

    public RiskPolicyService(
            RiskPolicyRepository riskPolicyRepository,
            InventoryComponentRepository inventoryComponentRepository,
            ObjectProvider<FindingDeltaQueueService> findingDeltaQueueServiceProvider,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            PlatformTransactionManager transactionManager
    ) {
        this.riskPolicyRepository = riskPolicyRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.findingDeltaQueueServiceProvider = findingDeltaQueueServiceProvider;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public RiskPolicy getOrCreate(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            RiskPolicy policy = writeTransactionTemplate.execute(status -> getOrCreateInCurrentTenantSchema(tenant));
            return policy == null ? getOrCreateInCurrentTenantSchema(tenant) : policy;
        });
    }

    public RiskPolicyResponse update(Tenant tenant, RiskPolicyRequest req) {
        UpdateResult updateResult = tenantSchemaExecutionService.run(tenant, () -> {
            UpdateResult result = writeTransactionTemplate.execute(status -> updateInCurrentTenantSchema(tenant, req));
            return result == null ? updateInCurrentTenantSchema(tenant, req) : result;
        });
        enqueueAutomaticFindingRecomputeIfEnabled(tenant, updateResult.previousMode(), updateResult.saved().getFindingGenerationMode());
        return toResponse(updateResult.saved());
    }

    public RiskPolicyResponse get(Tenant tenant) {
        return toResponse(getOrCreate(tenant));
    }

    public String getFindingsScoreConfig(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            String scoreConfig = readTransactionTemplate.execute(status -> riskPolicyRepository.findTopByOrderByUpdatedAtDesc()
                    .map(RiskPolicy::getFindingsScoreConfig)
                    .orElse(RiskPolicyPresets.DEFAULT_FINDINGS_SCORE_CONFIG_JSON));
            return scoreConfig == null ? RiskPolicyPresets.DEFAULT_FINDINGS_SCORE_CONFIG_JSON : scoreConfig;
        });
    }

    private RiskPolicy getOrCreateInCurrentTenantSchema(Tenant tenant) {
        return riskPolicyRepository.findTopByOrderByUpdatedAtDesc()
                .orElseGet(() -> {
                    RiskPolicy policy = new RiskPolicy();
                    policy.setTenant(tenant);
                    policy.setFindingsScoreConfig(RiskPolicyPresets.DEFAULT_FINDINGS_SCORE_CONFIG_JSON);
                    return riskPolicyRepository.save(policy);
                });
    }

    private UpdateResult updateInCurrentTenantSchema(Tenant tenant, RiskPolicyRequest req) {
        RiskPolicy policy = getOrCreateInCurrentTenantSchema(tenant);
        RiskPolicy.FindingGenerationMode previousMode = policy.getFindingGenerationMode();

        if (req.criticalThreshold() != null) {
            policy.setCriticalThreshold(req.criticalThreshold());
        }
        if (req.highThreshold() != null) {
            policy.setHighThreshold(req.highThreshold());
        }
        if (req.criticalSlaDays() != null) {
            policy.setCriticalSlaDays(Math.max(0, req.criticalSlaDays()));
        }
        if (req.highSlaDays() != null) {
            policy.setHighSlaDays(Math.max(0, req.highSlaDays()));
        }
        if (req.mediumSlaDays() != null) {
            policy.setMediumSlaDays(Math.max(0, req.mediumSlaDays()));
        }
        if (req.lowSlaDays() != null) {
            policy.setLowSlaDays(Math.max(0, req.lowSlaDays()));
        }
        if (req.assetCriticalSlaMultiplier() != null) {
            policy.setAssetCriticalSlaMultiplier(Math.max(0.0, req.assetCriticalSlaMultiplier()));
        }
        if (req.assetHighSlaMultiplier() != null) {
            policy.setAssetHighSlaMultiplier(Math.max(0.0, req.assetHighSlaMultiplier()));
        }
        if (req.assetMediumSlaMultiplier() != null) {
            policy.setAssetMediumSlaMultiplier(Math.max(0.0, req.assetMediumSlaMultiplier()));
        }
        if (req.assetLowSlaMultiplier() != null) {
            policy.setAssetLowSlaMultiplier(Math.max(0.0, req.assetLowSlaMultiplier()));
        }
        if (req.autoCloseEnabled() != null) {
            policy.setAutoCloseEnabled(req.autoCloseEnabled());
        }
        if (req.autoCloseAssetIdentifier() != null) {
            String trimmed = req.autoCloseAssetIdentifier().trim();
            policy.setAutoCloseAssetIdentifier(trimmed.isEmpty() ? null : trimmed);
        }
        if (req.autoCloseAfterDays() != null) {
            policy.setAutoCloseAfterDays(Math.max(0, req.autoCloseAfterDays()));
        }
        if (req.autoCloseRequiredConsecutiveMisses() != null) {
            policy.setAutoCloseRequiredConsecutiveMisses(req.autoCloseRequiredConsecutiveMisses());
        }
        if (req.autoCloseNotObservedEnabled() != null) {
            policy.setAutoCloseNotObservedEnabled(req.autoCloseNotObservedEnabled());
        }
        if (req.autoCloseComponentRemovedEnabled() != null) {
            policy.setAutoCloseComponentRemovedEnabled(req.autoCloseComponentRemovedEnabled());
        }
        if (req.autoCloseAssetRetiredEnabled() != null) {
            policy.setAutoCloseAssetRetiredEnabled(req.autoCloseAssetRetiredEnabled());
        }
        if (req.autoCloseSourceDisabledEnabled() != null) {
            policy.setAutoCloseSourceDisabledEnabled(req.autoCloseSourceDisabledEnabled());
        }
        if (req.autoCloseDuplicateEnabled() != null) {
            policy.setAutoCloseDuplicateEnabled(req.autoCloseDuplicateEnabled());
        }
        if (req.autoCloseRunIntervalDays() != null) {
            policy.setAutoCloseRunIntervalDays(req.autoCloseRunIntervalDays());
        }
        if (req.findingGenerationMode() != null) {
            policy.setFindingGenerationMode(parseFindingGenerationMode(req.findingGenerationMode()));
        }
        if (req.findingsScoreConfig() != null) {
            policy.setFindingsScoreConfig(req.findingsScoreConfig());
        }
        if (req.agentAutoThreshold() != null) {
            policy.setAgentAutoThreshold(Math.max(0.0, Math.min(1.0, req.agentAutoThreshold())));
        }
        if (req.agentReviewThreshold() != null) {
            policy.setAgentReviewThreshold(Math.max(0.0, Math.min(1.0, req.agentReviewThreshold())));
        }
        if (req.agentMaxConcurrent() != null) {
            policy.setAgentMaxConcurrent(Math.max(1, req.agentMaxConcurrent()));
        }

        policy.touch();
        RiskPolicy saved = riskPolicyRepository.save(policy);
        return new UpdateResult(saved, previousMode);
    }

    private RiskPolicyResponse toResponse(RiskPolicy policy) {
        return new RiskPolicyResponse(
                policy.getCriticalThreshold(),
                policy.getHighThreshold(),
                policy.getCriticalSlaDays(),
                policy.getHighSlaDays(),
                policy.getMediumSlaDays(),
                policy.getLowSlaDays(),
                policy.getAssetCriticalSlaMultiplier(),
                policy.getAssetHighSlaMultiplier(),
                policy.getAssetMediumSlaMultiplier(),
                policy.getAssetLowSlaMultiplier(),
                policy.isAutoCloseEnabled(),
                policy.getAutoCloseAssetIdentifier(),
                policy.getAutoCloseAfterDays(),
                policy.getFindingGenerationMode().name(),
                policy.getFindingsScoreConfig(),
                policy.getAgentAutoThreshold(),
                policy.getAgentReviewThreshold(),
                policy.getAgentMaxConcurrent(),
                policy.getAutoCloseRequiredConsecutiveMisses(),
                policy.isAutoCloseNotObservedEnabled(),
                policy.isAutoCloseComponentRemovedEnabled(),
                policy.isAutoCloseAssetRetiredEnabled(),
                policy.isAutoCloseSourceDisabledEnabled(),
                policy.isAutoCloseDuplicateEnabled(),
                policy.getAutoCloseRunIntervalDays(),
                policy.getAutoCloseLastRunAt());
    }

    private RiskPolicy.FindingGenerationMode parseFindingGenerationMode(String value) {
        if (value == null || value.isBlank()) {
            return RiskPolicy.FindingGenerationMode.MANUAL;
        }
        try {
            return RiskPolicy.FindingGenerationMode.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return RiskPolicy.FindingGenerationMode.MANUAL;
        }
    }

    private void enqueueAutomaticFindingRecomputeIfEnabled(
            Tenant tenant,
            RiskPolicy.FindingGenerationMode previousMode,
            RiskPolicy.FindingGenerationMode nextMode
    ) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        if (previousMode == RiskPolicy.FindingGenerationMode.AUTO || nextMode != RiskPolicy.FindingGenerationMode.AUTO) {
            return;
        }
        List<UUID> componentIds = tenantSchemaExecutionService.run(
                tenant,
                () -> inventoryComponentRepository.findIdsByComponentStatus(InventoryComponentStatus.ACTIVE)
        )
                .stream()
                .filter(id -> id != null)
                .toList();
        if (componentIds.isEmpty()) {
            return;
        }
        FindingDeltaQueueService findingDeltaQueueService = findingDeltaQueueServiceProvider.getIfAvailable();
        if (findingDeltaQueueService == null) {
            return;
        }
        findingDeltaQueueService.enqueueSoftwareDeltas(tenant.getId(), componentIds, "risk-policy-auto-enable");
        findingDeltaQueueService.enqueueNoiseReductionRefresh(tenant.getId(), "risk-policy-auto-enable");
    }

    private record UpdateResult(RiskPolicy saved, RiskPolicy.FindingGenerationMode previousMode) {
    }
}
