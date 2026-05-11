package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RiskPolicyService {

    private final RiskPolicyRepository riskPolicyRepository;

    public RiskPolicyService(RiskPolicyRepository riskPolicyRepository) {
        this.riskPolicyRepository = riskPolicyRepository;
    }

    @Transactional
    public RiskPolicy getOrCreate(Tenant tenant) {
        return riskPolicyRepository.findByTenant(tenant)
                .orElseGet(() -> {
                    RiskPolicy policy = new RiskPolicy();
                    policy.setTenant(tenant);
                    return riskPolicyRepository.save(policy);
                });
    }

    @Transactional
    public RiskPolicyResponse update(Tenant tenant, RiskPolicyRequest req) {
        RiskPolicy policy = getOrCreate(tenant);

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
        if (req.findingGenerationMode() != null) {
            policy.setFindingGenerationMode(parseFindingGenerationMode(req.findingGenerationMode()));
        }
        if (req.findingsScoreConfig() != null) {
            policy.setFindingsScoreConfig(req.findingsScoreConfig());
        }

        policy.touch();
        return toResponse(riskPolicyRepository.save(policy));
    }

    public RiskPolicyResponse get(Tenant tenant) {
        return toResponse(getOrCreate(tenant));
    }

    @Transactional(readOnly = true)
    public String getFindingsScoreConfig(Tenant tenant) {
        return riskPolicyRepository.findByTenant(tenant)
                .map(RiskPolicy::getFindingsScoreConfig)
                .orElse("[]");
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
                policy.getFindingsScoreConfig());
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
}
